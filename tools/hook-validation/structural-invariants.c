#include "hook-validate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

/* Source-of-truth constants for the pinned reference build
   (audiodg 26100.9444; tools/endpoint-probe/Native-Hook.c:70,80 and
   Native-Hook-Control.c:74). They are used only to calibrate/validate the
   structural profile against the reference image; candidate builds are located
   purely from structure. */
#define REF_TARGET_RVA 0x31930u
#define REF_VT1_RVA 0x9f4f8u
#define REF_VT2_RVA 0xa2d58u
#define REF_TARGET_SIZE 474u
#define REF_TARGET_PROLOGUE_LEN 16u

#define MAX_SIGS 256

typedef struct {
  uint32_t rva;
  uint32_t size;
  uint16_t refs;
  uint8_t kinds;
  uint8_t kinds_mask;
  uint16_t nslots;
  uint32_t slots[HV_MAX_SLOTS_PER_FN];
} SigFn;

typedef struct {
  HvPeImage pe;
  HvFunction fns[HV_MAX_FUNCS];
  int nfun;
  HvRef refs[HV_MAX_REFS];
  int nrefs;
  SigFn sigs[MAX_SIGS];
  int nsig;
} ImageAnalysis;

static int analyze(const char *path,ImageAnalysis *a){
  memset(a,0,sizeof(*a));
  if(hv_pe_load(&a->pe,path)!=0)return -1;
  a->nfun=hv_pe_functions(&a->pe,a->fns,HV_MAX_FUNCS);
  if(a->nfun<=0)return -1;
  a->nrefs=hv_pe_scan_refs(&a->pe,a->fns,a->nfun,a->refs,HV_MAX_REFS);
  for(int i=0;i<a->nfun&&a->nsig<MAX_SIGS;i++){
    HvFunction *f=&a->fns[i];
    int mask=hv_kinds(&a->pe,f);
    if(mask<0)continue;
    int kinds=0;for(int b=0;b<8;b++)if(mask&(1<<b))kinds++;
    if(kinds<3||f->ref_count<2)continue;
    SigFn *s=&a->sigs[a->nsig++];
    s->rva=f->begin;s->size=f->end-f->begin;s->refs=f->ref_count;
    s->kinds=(uint8_t)kinds;s->kinds_mask=(uint8_t)mask;s->nslots=f->slot_count;
    for(int k=0;k<f->slot_count&&k<HV_MAX_SLOTS_PER_FN;k++)s->slots[k]=f->slots[k];
  }
  return 0;
}

static void json_str(char *out,size_t cap,const char *s){
  size_t o=0;out[o++]='"';
  for(;*s&&o+8<cap;s++){
    unsigned char c=(unsigned char)*s;
    if(c=='\\'||c=='"'){out[o++]='\\';out[o++]=(char)c;}
    else if(c<0x20){o+=(size_t)snprintf(out+o,cap-o,"\\u%04x",c);}
    else out[o++]=(char)c;
  }
  out[o++]='"';out[o]=0;
}

static void ver_str(const HvPeImage *pe,char *out,size_t cap){
  if(pe->file_version[0]||pe->file_version[2])
    snprintf(out,cap,"%u.%u.%u.%u",pe->file_version[0],pe->file_version[1],pe->file_version[2],pe->file_version[3]);
  else snprintf(out,cap,"unknown");
}

static int find_slot_function(ImageAnalysis *a,uint32_t slot_rva,uint32_t *fn_rva){
  uint8_t b[8];
  if(hv_pe_read(&a->pe,slot_rva,b,8)!=8)return 0;
  uint64_t v=((uint64_t)b[0])|((uint64_t)b[1]<<8)|((uint64_t)b[2]<<16)|((uint64_t)b[3]<<24)|
             ((uint64_t)b[4]<<32)|((uint64_t)b[5]<<40)|((uint64_t)b[6]<<48)|((uint64_t)b[7]<<56);
  if(v<a->pe.image_base)return 0;
  uint64_t rva=v-a->pe.image_base;
  if(rva>=a->pe.size_of_image)return 0;
  *fn_rva=(uint32_t)rva;
  return 1;
}

/* Find the contiguous code-pointer run that hosts the field-access signature
   cluster, then infer the vtable base. Reference profile: the four accessor
   methods occupy vtable slots 3..6 (vtable+0x18..vtable+0x30) and the run that
   contains the vtable starts 0x350 bytes before the vtable base (RTTI and
   neighbouring tables), so cluster_min_slot-0x18 is the vtable base estimate.
   The run with the largest signature-slot cluster wins; the pinned reference
   build has one cluster per family, each with four slots. */
static int locate_vtable_run(ImageAnalysis *a,
                             uint32_t *run_base,uint32_t *vt_est,uint32_t *cluster_min,
                             uint32_t *cluster_slots,int *ncluster){
  if(a->nsig<2)return 0;
  uint32_t slots[64];int n=0;
  for(int i=0;i<a->nsig&&n<64;i++)
    for(int k=0;k<a->sigs[i].nslots&&n<64;k++)slots[n++]=a->sigs[i].slots[k];
  uint32_t best_base=0,best_min=0,best_slots[8]={0};int best_count=0;
  for(int i=0;i<n;i++){
    uint32_t rb,re;hv_run_bounds(&a->pe,slots[i],&rb,&re);
    uint32_t min_slot=0xffffffffu;int count=0;uint32_t my[8]={0};
    for(int j=0;j<n;j++){
      if(slots[j]<rb||slots[j]>re)continue;
      if(count<8)my[count]=slots[j];
      count++;
      if(slots[j]<min_slot)min_slot=slots[j];
    }
    if(count<2)continue;
    if(count>best_count){
      best_count=count>8?8:count;best_base=rb;best_min=min_slot;
      for(int k=0;k<best_count;k++)best_slots[k]=my[k];
    }
  }
  if(!best_count)return 0;
  *run_base=best_base;*cluster_min=best_min;*ncluster=best_count;
  for(int k=0;k<best_count;k++)cluster_slots[k]=best_slots[k];
  *vt_est=best_min-0x18u;
  return 1;
}

int run_structural_invariants(const char *ref_path,const char *cand_path);

int run_structural_invariants(const char *ref_path,const char *cand_path){
  LARGE_INTEGER f,t0,t1;QueryPerformanceFrequency(&f);QueryPerformanceCounter(&t0);
  static ImageAnalysis ref,cand; /* large tables: keep off the 1 MiB default stack */
  int rc=1;
  if(analyze(ref_path,&ref)!=0){fprintf(stderr,"cannot parse reference: %s\n",ref_path);return 3;}
  if(analyze(cand_path,&cand)!=0){fprintf(stderr,"cannot parse candidate: %s\n",cand_path);hv_pe_free(&ref.pe);return 3;}

  /* ---- reference calibration ---- */
  int ref_idx=hv_find_function(ref.fns,ref.nfun,REF_TARGET_RVA);
  int ref_target_ok=ref_idx>=0&&ref.fns[ref_idx].ref_count>=2;
  uint32_t ref_vt1=0,ref_vt2=0;
  int ref_vt1_known=0,ref_vt2_known=0;
  for(int i=0;i<ref.nsig;i++){
    SigFn *s=&ref.sigs[i];
    for(int k=0;k<s->nslots;k++){
      if(s->slots[k]>=REF_VT1_RVA&&s->slots[k]<REF_VT1_RVA+0x200)ref_vt1_known++;
      if(s->slots[k]>=REF_VT2_RVA&&s->slots[k]<REF_VT2_RVA+0x200)ref_vt2_known++;
    }
  }
  (void)ref_vt1;(void)ref_vt2;

  /* ---- candidate structural analysis ---- */
  uint32_t run_base=0,vt_est=0,cluster_min=0,cluster_slots[8]={0};
  int ncluster=0;
  int have_run=locate_vtable_run(&cand,&run_base,&vt_est,&cluster_min,cluster_slots,&ncluster);

  uint32_t target_rva=0;int target_found=0,slot_index=-1;uint32_t target_slot=0;
  if(have_run){
    target_slot=vt_est+0x100u;
    uint32_t fn_rva=0;
    if(find_slot_function(&cand,target_slot,&fn_rva)&&hv_find_function(cand.fns,cand.nfun,fn_rva)>=0){
      int fi=hv_find_function(cand.fns,cand.nfun,fn_rva);
      if(cand.fns[fi].ref_count>=2){
        target_rva=fn_rva;target_found=1;slot_index=(int)((target_slot-vt_est)/8u);
      }
    }
  }
  int same_build=ref.pe.timestamp==cand.pe.timestamp&&ref.pe.size_of_image==cand.pe.size_of_image&&ref.pe.checksum==cand.pe.checksum;
  int vt1_matches_known=have_run&&vt_est==REF_VT1_RVA;
  int candidate_signature_ok=cand.nsig>=2&&have_run;
  int target_size=target_found?(int)(cand.fns[hv_find_function(cand.fns,cand.nfun,target_rva)].end-target_rva):0;

  const char *decision;
  if(candidate_signature_ok&&target_found&&same_build&&ref_target_ok)decision="allow";
  else if(candidate_signature_ok&&target_found)decision="warn";
  else if(cand.nsig>0)decision="unknown";
  else decision="deny";

  QueryPerformanceCounter(&t1);
  double ms=1000.0*(double)(t1.QuadPart-t0.QuadPart)/(double)f.QuadPart;

  char rj[1024],cj[1024],cfg[32];
  json_str(rj,sizeof(rj),ref_path);json_str(cj,sizeof(cj),cand_path);ver_str(&cand.pe,cfg,sizeof(cfg));

  printf("{\n");
  printf("  \"method\": \"structural-invariants\",\n");
  printf("  \"reference\": %s,\n",rj);
  printf("  \"candidate\": %s,\n",cj);
  printf("  \"build\": {\"fileVersion\": \"%s\", \"timeDateStamp\": %u, \"sizeOfImage\": %u, \"checksum\": %u},\n",
         cfg,(unsigned)cand.pe.timestamp,(unsigned)cand.pe.size_of_image,(unsigned)cand.pe.checksum);
  if(target_found)
    printf("  \"located\": {\"rva\": %u, \"size\": %u, \"confidence\": %.2f},\n",
           (unsigned)target_rva,(unsigned)target_size,vt1_matches_known?0.95:0.82);
  else printf("  \"located\": null,\n");
  printf("  \"decision\": \"%s\",\n",decision);
  printf("  \"targetChanged\": null,\n");
  printf("  \"checks\": [\n");

  /* 1. PE parsing */
  printf("    {\"name\": \"pe-parse\", \"ok\": true, \"detail\": \"imageBase=0x%llx sections=%d .text/.pdata/.rdata/.data parsed; fileVersion=%s\"},\n",
         (unsigned long long)cand.pe.image_base,cand.pe.nsec,cfg);
  /* 2. .pdata candidate set */
  printf("    {\"name\": \"pdata-candidates\", \"ok\": %s, \"detail\": \"reference=%d functions, candidate=%d functions\"},\n",
         cand.nfun>0?"true":"false",ref.nfun,cand.nfun);
  /* 3. pointer refs */
  printf("    {\"name\": \"code-pointer-refs\", \"ok\": %s, \"detail\": \"%d 8-byte qwords in .rdata/.data equal ImageBase+candidate entry (reference=%d)\"},\n",
         cand.nrefs>0?"true":"false",cand.nrefs,ref.nrefs);
  /* 4. structural signature (>=3 field disp kinds, >=2 refs) */
  {
    char det[1024];int o=0;
    o+=snprintf(det+o,sizeof(det)-o,"candidate signature functions=%d (need >=3 distinct of 0x510/0x5d0/0x5d4/0x5d8/0xC/0x14/0x28/0x38 and >=2 refs):",cand.nsig);
    for(int i=0;i<cand.nsig&&o<(int)sizeof(det)-80;i++)
      o+=snprintf(det+o,sizeof(det)-o," %s0x%x(k=%u,refs=%u)",i?",":"",cand.sigs[i].rva,cand.sigs[i].kinds,cand.sigs[i].refs);
    printf("    {\"name\": \"field-access-signature\", \"ok\": %s, \"detail\": \"%s\"},\n",cand.nsig>=2?"true":"false",det);
  }
  /* 5. vtable run/base inference */
  if(have_run)
    printf("    {\"name\": \"vtable-base-inference\", \"ok\": true, \"detail\": \"runBegin=0x%x clusterMinSlot=0x%x inferredVtable=0x%x (%u signature slots in run; reference layout matches known vtable 0x%x: %s)\"},\n",
           run_base,cluster_min,vt_est,(unsigned)ncluster,REF_VT1_RVA,vt1_matches_known?"yes":"no (recompiled build)");
  else
    printf("    {\"name\": \"vtable-base-inference\", \"ok\": false, \"detail\": \"no contiguous code-pointer run hosts the signature cluster\"},\n");
  /* 6. known vtable validation on the reference build */
  printf("    {\"name\": \"known-vtable-validation\", \"ok\": %s, \"detail\": \"reference target rva=0x%x in .pdata=%s refs=%d; signature slots inside pinned vt1(0x%x)/vt2(0x%x) windows=%d/%d (slot offsets are vtable+0x18..0x30, not the vtable base)\"},\n",
         (ref_target_ok&&ref_vt1_known>=4&&ref_vt2_known>=4)?"true":"false",
         REF_TARGET_RVA,ref_idx>=0?"yes":"no",ref_idx>=0?ref.fns[ref_idx].ref_count:0,
         REF_VT1_RVA,REF_VT2_RVA,ref_vt1_known,ref_vt2_known);
  /* 7. target located */
  if(target_found)
    printf("    {\"name\": \"target-located\", \"ok\": true, \"detail\": \"slotRva=0x%x slotIndex=%d vtableRva=0x%x targetSize=%u refs=%u (slot-relative structural anchor)\"},\n",
           target_slot,slot_index,vt_est,(unsigned)target_size,
           (unsigned)cand.fns[hv_find_function(cand.fns,cand.nfun,target_rva)].ref_count);
  else
    printf("    {\"name\": \"target-located\", \"ok\": false, \"detail\": \"no function referenced at inferredVtable+0x100 with >=2 refs\"},\n");
  /* 8. body bytes not verified -- honest limitation */
  printf("    {\"name\": \"body-bytes\", \"ok\": false, \"detail\": \"this method does NOT verify function body bytes: a 1-byte mutation at +0x60 is undetectable unless it lands on the prologue or a field-displacement constant\"}\n");
  printf("  ],\n");
  printf("  \"timingMs\": %.3f\n",ms);
  printf("}\n");
  rc=0;
  hv_pe_free(&ref.pe);hv_pe_free(&cand.pe);
  return rc;
}