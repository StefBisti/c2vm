#ifndef C2VM_PUBLISH_H
#define C2VM_PUBLISH_H

// signing needs the digest, not the tag
char *oci_digest(const char *oras, const char *ref);


// push the disk to oras
int cmd_push(int argc, char *argv[]);

// sign that it was you who published that
int cmd_sign(int argc, char *argv[]);


int cmd_attest(int argc, char *argv[]);

#endif
