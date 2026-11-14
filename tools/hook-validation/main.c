#include <stdio.h>
#include <string.h>

int run_structural_invariants(const char *ref_path,const char *cand_path);

static void usage(void){
  fprintf(stderr,"usage: nsp-hook-validate --method <m> --reference <ref.exe> --candidate <cand.exe> [--json]\n");
  fprintf(stderr,"methods: structural-invariants\n");
}

int main(int argc,char **argv){
  const char *method=NULL,*ref=NULL,*cand=NULL;int json=0;
  for(int i=1;i<argc;i++){
    if(!strcmp(argv[i],"--method")&&i+1<argc)method=argv[++i];
    else if(!strcmp(argv[i],"--reference")&&i+1<argc)ref=argv[++i];
    else if(!strcmp(argv[i],"--candidate")&&i+1<argc)cand=argv[++i];
    else if(!strcmp(argv[i],"--json"))json=1;
    else {fprintf(stderr,"unknown argument: %s\n",argv[i]);usage();return 2;}
  }
  if(!method||!ref||!cand){usage();return 2;}
  if(strcmp(method,"structural-invariants")){fprintf(stderr,"unsupported method: %s\n",method);return 2;}
  (void)json; /* stdout is always a single JSON object by contract */
  return run_structural_invariants(ref,cand);
}
