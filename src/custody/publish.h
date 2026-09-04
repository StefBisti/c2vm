#ifndef C2VM_PUBLISH_H
#define C2VM_PUBLISH_H

/* Resolves a tag to the manifest digest it currently points at. Everything
   signs the digest: a tag can be repointed the moment after it is signed. */
char *oci_digest(const char *oras, const char *ref);

int cmd_push(int argc, char *argv[]);
int cmd_sign(int argc, char *argv[]);
int cmd_attest(int argc, char *argv[]);

#endif
