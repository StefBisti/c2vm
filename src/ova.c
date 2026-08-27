#include "ova.h"
#include "run.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// CIM resource types, from DMTF CIM_ResourceAllocationSettingData.
#define RASD_PROCESSOR 3
#define RASD_MEMORY 4
#define RASD_SCSI_CONTROLLER 6
#define RASD_ETHERNET 10
#define RASD_DISK 17

#define OVA_CPUS 2
#define OVA_MEMORY_MB 2048

static unsigned long long file_size(const char *path)
{
    if (dry_run)
        return 0;

    struct stat st;
    if (stat(path, &st) != 0)
        die("cannot stat %s: %s", path, strerror(errno));
    return (unsigned long long)st.st_size;
}

static char *sha256_of(const char *path)
{
    char *out = run_capture("sha256sum", path, NULL);
    char *sp = strchr(out, ' ');
    if (sp)
        *sp = '\0';
    return out;
}

// xml escapes
static const char *X(const char *s)
{
    static char buf[512];
    size_t w = 0;

    for (const char *p = s; *p && w < sizeof buf - 8; p++)
    {
        const char *rep = NULL;

        switch (*p)
        {
        case '&':
            rep = "&amp;";
            break;
        case '<':
            rep = "&lt;";
            break;
        case '>':
            rep = "&gt;";
            break;
        case '"':
            rep = "&quot;";
            break;
        case '\'':
            rep = "&apos;";
            break;
        default:
            buf[w++] = *p;
            continue;
        }

        size_t n = strlen(rep);
        memcpy(buf + w, rep, n);
        w += n;
    }
    buf[w] = '\0';

    return buf;
}

static void convert_vmdk(const char *outdir)
{
    step("converting to vmdk (streamOptimized)");
    run_ok("qemu-img", "convert", "-f", "raw", "-O", "vmdk",
           "-o", "subformat=streamOptimized,adapter_type=lsilogic",
           P("%s/disk.raw", outdir), P("%s/disk.vmdk", outdir), NULL);
}

static void write_ovf(const char *outdir, const char *name)
{
    step("writing OVF descriptor");

    unsigned long long capacity = file_size(P("%s/disk.raw", outdir));
    unsigned long long vmdk_size = file_size(P("%s/disk.vmdk", outdir));

    write_file(P("%s/disk.ovf", outdir),
               "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<Envelope ovf:version=\"1.0\" xml:lang=\"en-US\"\n"
               "  xmlns=\"http://schemas.dmtf.org/ovf/envelope/1\"\n"
               "  xmlns:ovf=\"http://schemas.dmtf.org/ovf/envelope/1\"\n"
               "  xmlns:rasd=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
               "CIM_ResourceAllocationSettingData\"\n"
               "  xmlns:vssd=\"http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
               "CIM_VirtualSystemSettingData\"\n"
               "  xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n"
               "  <References>\n"
               "    <File ovf:href=\"disk.vmdk\" ovf:id=\"file1\" ovf:size=\"%llu\"/>\n"
               "  </References>\n"
               "  <DiskSection>\n"
               "    <Info>Virtual disk information</Info>\n"
               "    <Disk ovf:capacity=\"%llu\" ovf:capacityAllocationUnits=\"byte\"\n"
               "          ovf:diskId=\"vmdisk1\" ovf:fileRef=\"file1\"\n"
               "          ovf:format=\"http://www.vmware.com/interfaces/specifications/"
               "vmdk.html#streamOptimized\"\n"
               "          ovf:populatedSize=\"%llu\"/>\n"
               "  </DiskSection>\n"
               "  <NetworkSection>\n"
               "    <Info>The list of logical networks</Info>\n"
               "    <Network ovf:name=\"nat\">\n"
               "      <Description>Network the guest takes a DHCP lease on</Description>\n"
               "    </Network>\n"
               "  </NetworkSection>\n"
               "  <VirtualSystem ovf:id=\"%s\">\n"
               "    <Info>A container image converted to a virtual machine by c2vm</Info>\n"
               "    <Name>%s</Name>\n"
               "    <OperatingSystemSection ovf:id=\"94\">\n"
               "      <Info>The kind of installed guest operating system</Info>\n"
               "      <Description>Ubuntu Linux (64-bit)</Description>\n"
               "    </OperatingSystemSection>\n"
               "    <VirtualHardwareSection>\n"
               "      <Info>Virtual hardware requirements</Info>\n"
               "      <System>\n"
               "        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>\n"
               "        <vssd:InstanceID>0</vssd:InstanceID>\n"
               "        <vssd:VirtualSystemIdentifier>%s</vssd:VirtualSystemIdentifier>\n"
               "        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>\n"
               "      </System>\n"
               "      <Item>\n"
               "        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>\n"
               "        <rasd:Description>Number of virtual CPUs</rasd:Description>\n"
               "        <rasd:ElementName>%d virtual CPU(s)</rasd:ElementName>\n"
               "        <rasd:InstanceID>1</rasd:InstanceID>\n"
               "        <rasd:ResourceType>%d</rasd:ResourceType>\n"
               "        <rasd:VirtualQuantity>%d</rasd:VirtualQuantity>\n"
               "      </Item>\n"
               "      <Item>\n"
               "        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>\n"
               "        <rasd:Description>Memory Size</rasd:Description>\n"
               "        <rasd:ElementName>%d MB of memory</rasd:ElementName>\n"
               "        <rasd:InstanceID>2</rasd:InstanceID>\n"
               "        <rasd:ResourceType>%d</rasd:ResourceType>\n"
               "        <rasd:VirtualQuantity>%d</rasd:VirtualQuantity>\n"
               "      </Item>\n"
               "      <Item>\n"
               "        <rasd:Address>0</rasd:Address>\n"
               "        <rasd:Description>SCSI Controller</rasd:Description>\n"
               "        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>\n"
               "        <rasd:InstanceID>3</rasd:InstanceID>\n"
               "        <rasd:ResourceSubType>lsilogic</rasd:ResourceSubType>\n"
               "        <rasd:ResourceType>%d</rasd:ResourceType>\n"
               "      </Item>\n"
               "      <Item>\n"
               "        <rasd:AddressOnParent>0</rasd:AddressOnParent>\n"
               "        <rasd:ElementName>Hard Disk 1</rasd:ElementName>\n"
               "        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>\n"
               "        <rasd:InstanceID>4</rasd:InstanceID>\n"
               "        <rasd:Parent>3</rasd:Parent>\n"
               "        <rasd:ResourceType>%d</rasd:ResourceType>\n"
               "      </Item>\n"
               "      <Item>\n"
               "        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>\n"
               "        <rasd:Connection>nat</rasd:Connection>\n"
               "        <rasd:ElementName>Ethernet adapter 0</rasd:ElementName>\n"
               "        <rasd:InstanceID>5</rasd:InstanceID>\n"
               "        <rasd:ResourceSubType>E1000</rasd:ResourceSubType>\n"
               "        <rasd:ResourceType>%d</rasd:ResourceType>\n"
               "      </Item>\n"
               "    </VirtualHardwareSection>\n"
               "  </VirtualSystem>\n"
               "</Envelope>\n",
               vmdk_size, capacity, vmdk_size,
               X(name), X(name), X(name),
               OVA_CPUS, RASD_PROCESSOR, OVA_CPUS,
               OVA_MEMORY_MB, RASD_MEMORY, OVA_MEMORY_MB,
               RASD_SCSI_CONTROLLER,
               RASD_DISK,
               RASD_ETHERNET);
}

static void write_manifest(const char *outdir)
{
    step("writing OVF manifest");

    char *ovf_hash = sha256_of(P("%s/disk.ovf", outdir));
    char *vmdk_hash = sha256_of(P("%s/disk.vmdk", outdir));

    write_file(P("%s/disk.mf", outdir),
               "SHA256(disk.ovf)= %s\n"
               "SHA256(disk.vmdk)= %s\n",
               ovf_hash, vmdk_hash);

    free(ovf_hash);
    free(vmdk_hash);
}

// --format=ustar because DSP0243 requires it
static void write_tar(const char *outdir)
{
    step("packing OVA");
    run_ok("tar", "--format=ustar", "-cf", P("%s/disk.ova", outdir), "-C", outdir,
           "disk.ovf", "disk.mf", "disk.vmdk", NULL);
}

static void discard_members(const char *outdir)
{
    run_ok("rm", "-f", P("%s/disk.vmdk", outdir), P("%s/disk.ovf", outdir),
           P("%s/disk.mf", outdir), NULL);
}

void ova_write(const char *outdir, const char *name)
{
    convert_vmdk(outdir);
    write_ovf(outdir, name);
    write_manifest(outdir);
    write_tar(outdir);
    discard_members(outdir);
}
