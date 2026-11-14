#include "hook-validate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p){return (uint16_t)(p[0]|(p[1]<<8));}
static uint32_t rd32(const uint8_t *p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t rd64(const uint8_t *p){return (uint64_t)rd32(p)|((uint64_t)rd32(p+4)<<32);}

int hv_pe_load(HvPeImage *pe,const char *path){
  memset(pe,0,sizeof(*pe));
  FILE *f=fopen(path,"rb");if(!f)return -1;
  if(fseek(f,0,SEEK_END)!=0){fclose(f);return -1;}
  long n=ftell(f);if(n<0x100){fclose(f);return -1;}
  if(fseek(f,0,SEEK_SET)!=0){fclose(f);return -1;}
  pe->data=(uint8_t*)malloc((size_t)n);if(!pe->data){fclose(f);return -1;}
  if(fread(pe->data,1,(size_t)n,f)!=(size_t)n){fclose(f);hv_pe_free(pe);return -1;}
  fclose(f);pe->size=(size_t)n;
  const uint8_t *d=pe->data;
  if(d[0]!='M'||d[1]!='Z'||pe->size<0x40)goto bad;
  uint32_t e_lfanew=rd32(d+0x3c);
  if(e_lfanew+24>pe->size||memcmp(d+e_lfanew,"PE\0\0",4))goto bad;
  const uint8_t *coff=d+e_lfanew+4;
  if(rd16(coff)!=0x8664)goto bad; /* x64 only: audiodg is x64 */
  int nsec=rd16(coff+2);
  if(nsec<=0||nsec>HV_MAX_SECTIONS)goto bad;
  uint32_t optsize=rd16(coff+16);
  pe->timestamp=rd32(coff+4);
  const uint8_t *opt=coff+20;
  if(optsize<112||opt+optsize>d+pe->size)goto bad;
  if(rd16(opt)!=0x20b)goto bad; /* PE32+ */
  pe->image_base=rd64(opt+24);
  pe->size_of_image=rd32(opt+56);
  pe->checksum=rd32(opt+64);
  const uint8_t *sh=opt+optsize;
  if(sh+(size_t)nsec*40>d+pe->size)goto bad;
  for(int i=0;i<nsec;i++){
    HvSection *s=&pe->sec[i];const uint8_t *p=sh+i*40;int k=0;
    for(;k<8&&p[k];k++)s->name[k]=(char)p[k];
    s->name[k]=0;
    s->vsize=rd32(p+8);s->va=rd32(p+12);s->rawsize=rd32(p+16);s->rawptr=rd32(p+20);
  }
  pe->nsec=nsec;
  /* File version: locate VS_FIXEDFILEINFO (resource data, unique signature). */
  for(size_t i=0;i+52<pe->size;i++){
    if(d[i]==0xbd&&d[i+1]==0x04&&d[i+2]==0xef&&d[i+3]==0xfe){
      uint32_t msv=rd32(d+i+8),lsv=rd32(d+i+12);
      if((msv>>16)<=0xffff&&(msv&0xffff)<0x100){
        pe->file_version[0]=(uint16_t)(msv>>16);pe->file_version[1]=(uint16_t)msv;
        pe->file_version[2]=(uint16_t)(lsv>>16);pe->file_version[3]=(uint16_t)lsv;
        break;
      }
    }
  }
  return 0;
bad:
  hv_pe_free(pe);return -1;
}

void hv_pe_free(HvPeImage *pe){free(pe->data);pe->data=NULL;pe->size=0;}

const HvSection *hv_pe_section(const HvPeImage *pe,uint32_t rva){
  for(int i=0;i<pe->nsec;i++){
    const HvSection *s=&pe->sec[i];
    uint32_t span=s->vsize>s->rawsize?s->vsize:s->rawsize;
    if(rva>=s->va&&rva<s->va+span)return s;
  }
  return NULL;
}

size_t hv_pe_read(const HvPeImage *pe,uint32_t rva,void *out,size_t n){
  const HvSection *s=hv_pe_section(pe,rva);
  if(!s)return 0;
  uint32_t off=rva-s->va;
  if(off>=s->rawsize||s->rawptr+off>=pe->size)return 0;
  size_t avail=(size_t)s->rawsize-off;
  if(avail>pe->size-(size_t)(s->rawptr+off))avail=pe->size-(size_t)(s->rawptr+off);
  if(n>avail)n=avail;
  memcpy(out,pe->data+s->rawptr+off,n);
  return n;
}

static int cmp_fn(const void *a,const void *b){
  const HvFunction *x=(const HvFunction*)a,*y=(const HvFunction*)b;
  return x->begin<y->begin?-1:(x->begin>y->begin?1:0);
}

int hv_pe_functions(const HvPeImage *pe,HvFunction *fns,int max){
  const HvSection *pd=NULL;
  for(int i=0;i<pe->nsec;i++)if(!strcmp(pe->sec[i].name,".pdata"))pd=&pe->sec[i];
  if(!pd)return 0;
  int n=0;
  for(uint32_t off=0;off+12<=pd->rawsize&&n<max;off+=12){
    uint8_t e[12];
    if(hv_pe_read(pe,pd->va+off,e,sizeof(e))!=sizeof(e))break;
    uint32_t b=rd32(e),en=rd32(e+4);
    if(!b||!en||b>=en||en>pe->size_of_image)continue;
    fns[n].begin=b;fns[n].end=en;fns[n].ref_count=0;fns[n].kind_count=0;
    fns[n].kinds_mask=0;fns[n].slot_count=0;
    n++;
  }
  qsort(fns,(size_t)n,sizeof(fns[0]),cmp_fn);
  return n;
}

int hv_find_function(const HvFunction *fns,int nfun,uint32_t rva){
  int lo=0,hi=nfun-1;
  while(lo<=hi){
    int mid=(lo+hi)/2;
    if(fns[mid].begin==rva)return mid;
    if(fns[mid].begin<rva)lo=mid+1;else hi=mid-1;
  }
  return -1;
}

int hv_pe_scan_refs(const HvPeImage *pe,HvFunction *fns,int nfun,HvRef *refs,int maxrefs){
  int n=0;
  for(int i=0;i<pe->nsec;i++){
    const HvSection *s=&pe->sec[i];
    if(strcmp(s->name,".rdata")&&strcmp(s->name,".data"))continue;
    for(uint32_t off=0;off+8<=s->rawsize;off+=8){
      uint8_t b[8];
      if(hv_pe_read(pe,s->va+off,b,8)!=8)continue;
      uint64_t v=rd64(b);
      if(v<pe->image_base)continue;
      uint64_t rva=v-pe->image_base;
      if(rva>=pe->size_of_image)continue;
      int idx=hv_find_function(fns,nfun,(uint32_t)rva);
      if(idx<0)continue;
      if(n<maxrefs){refs[n].slot_rva=s->va+off;refs[n].func_rva=(uint32_t)rva;n++;}
      if(fns[idx].ref_count<0xffff)fns[idx].ref_count++;
      if(fns[idx].slot_count<HV_MAX_SLOTS_PER_FN)fns[idx].slots[fns[idx].slot_count++]=(uint32_t)(s->va+off);
    }
  }
  return n;
}

static const uint32_t hv_disp_values[8]={0x510,0x5d0,0x5d4,0x5d8,0xc,0x14,0x28,0x38};

/* Count distinct field-displacement constants reachable as a real disp32 memory
   operand. The byte before the little-endian disp32 must be a ModRM with
   mod=10 (0x80..0xbf), which suppresses the vast majority of false hits inside
   instruction streams. Small offsets (0x0c/0x14/0x28/0x38) are checked the same
   way: only genuine [reg+disp32] encodings count. */
int hv_kinds(const HvPeImage *pe,const HvFunction *fn){
  uint32_t len=fn->end-fn->begin;
  uint8_t *buf=(uint8_t*)malloc(len?len:1);
  if(!buf)return -1;
  size_t got=hv_pe_read(pe,fn->begin,buf,len);
  uint32_t mask=0;
  for(int k=0;k<8;k++){
    uint32_t v=hv_disp_values[k];
    for(size_t i=1;i+4<=got;i++){
      if(buf[i]!= (uint8_t)v||buf[i+1]!=(uint8_t)(v>>8)||buf[i+2]!=(uint8_t)(v>>16)||buf[i+3]!=(uint8_t)(v>>24))continue;
      if((buf[i-1]&0xc0)!=0x80)continue;
      mask|=(uint32_t)1<<k;break;
    }
  }
  free(buf);
  return (int)mask;
}

void hv_run_bounds(const HvPeImage *pe,uint32_t slot_rva,uint32_t *run_begin,uint32_t *run_end){
  const HvSection *text=NULL;
  for(int i=0;i<pe->nsec;i++)if(!strcmp(pe->sec[i].name,".text"))text=&pe->sec[i];
  uint32_t begin=slot_rva,end=slot_rva;
  if(text){
    uint8_t b[8];
    for(;;){
      if(begin<8)break;
      uint32_t prev=begin-8;
      if(hv_pe_read(pe,prev,b,8)!=8)break;
      uint64_t v=rd64(b);
      if(v<pe->image_base||v>=pe->image_base+pe->size_of_image)break;
      uint32_t rva=(uint32_t)(v-pe->image_base);
      if(rva<text->va||rva>=text->va+text->rawsize)break;
      begin=prev;
    }
    for(;;){
      if(end+8>=pe->size_of_image)break;
      if(hv_pe_read(pe,end+8,b,8)!=8)break;
      uint64_t v=rd64(b);
      if(v<pe->image_base||v>=pe->image_base+pe->size_of_image)break;
      uint32_t rva=(uint32_t)(v-pe->image_base);
      if(rva<text->va||rva>=text->va+text->rawsize)break;
      end+=8;
    }
  }
  *run_begin=begin;*run_end=end;
}
