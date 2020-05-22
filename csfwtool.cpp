#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <getopt.h>


typedef struct CS800D_header_ {
    uint32_t baseaddr_offset; // 0 - 0x08000000 + this (0x20000 or 0x10000 usually), 0 if spi flash data
    uint32_t unkaddr1; // 0x4 - 0
    uint32_t unkaddr2; // 0x8 - 0
    uint32_t rsrc_size; // 0xC - 0 if image bin, size if spi flash data (ex. 0x00069010 for RCDB)
    uint32_t unksize1; // 0x10 - 0
    uint32_t imagesize; // 0x14 - total image data size is this + imageHeaderSize 
    uint8_t padding1[0x24]; //0x18
    uint32_t rsrcHeaderSize; //0x3C - 0x80 if spi data, 0 if image data
    uint32_t unkHeaderSize; //0x40 - 0
    uint32_t imageHeaderSize; //0x44 - 0x80
    uint8_t padding2[0x24]; //0x48
    uint32_t version; // 0x6C - 0x00000001 usually 
    uint8_t resv[0x10]; // 0x70
}CS800D_header; // total size 0x80



void print_usage() {
    char strbuffer[1024];
    printf("Usage: csfwtool [option(s)] -i input.bin -o output.bin\n");
    printf("Examples:\n");
    printf("\tcsfwtool -e -i plaintext.bin -o image.bin\n");
    printf("\tcsfwtool -d -i stockfw.bin -o decrypted_unwrapped.bin\n");
    printf("Options:\n");

    #define PRINT_OPTION(short, long, hasarg, arg, comment) if(hasarg) { \
                snprintf(strbuffer, sizeof(strbuffer), "\t-%s [%s], --%s [%s]", short, arg, long, arg); \
            } else { \
                snprintf(strbuffer, sizeof(strbuffer), "\t-%s, --%s", short, long); \
            } printf("%s %*s\n", strbuffer, (int)(80 - strlen(strbuffer)), comment);
    #define PRINT_LONG_OPTION(long, hasarg, arg, comment) if(hasarg) { \
                snprintf(strbuffer, sizeof(strbuffer), "\t--%s [%s]", long, arg); \
            } else { \
                snprintf(strbuffer, sizeof(strbuffer), "\t--%s", long); \
            } printf("%s %*s\n", strbuffer, (int)(80 - strlen(strbuffer)), comment);

    PRINT_OPTION("h", "help", 0, "", "show this help message")
    PRINT_OPTION("i", "input", 1, "flash", "flash file input")
    PRINT_OPTION("o", "output", 1, "flash", "flash file output")
    PRINT_OPTION("d", "decrypt", 0, "", "decrypt input image file")
    PRINT_OPTION("e", "encrypt", 0, "", "encrypt and add header")
    PRINT_OPTION("r", "resource", 0, "", "specify resource type file (spi flash data)")
    PRINT_OPTION("b", "base", 1, "baseaddr", "specify base address offset (subtract 0x08000000) default: 0x20000")
    PRINT_OPTION("1", "CS800_cipher", 0, "", "(default) CS800 cipher")
    PRINT_OPTION("2", "DR5XX0_cipher", 0, "", "(default) DR5XX0 cipher")

}

const uint8_t xor_cipher_CS800[0x100] = { 0x60,0x5E,0x5D,0x5C,0x5A,0x59,0x36,0x34,0x33,0x31,0x30,0x2E,0x2D,0x2B,0x2A,0x28,
                                    0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x75,0x76,0x77,0x78,0x78,0x79,
                                    0x07,0x08,0x09,0x09,0x0A,0x0B,0x7A,0x04,0x05,0x06,0x06,0x7A,0x7B,0x7B,0x7C,0x7C,
                                    0x03,0x02,0x02,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x3F,0x41,0x42,0x44,0x45,0x47,
                                    0x0A,0x09,0x09,0x12,0x11,0x10,0x0F,0x0E,0x0D,0x0C,0x0B,0x08,0x07,0x06,0x06,0x05,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x02,0x02,0x03,0x03,0x04,
                                    0x7F,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,0x7D,0x7D,0x7D,0x7C,0x7C,0x7B,0x7B,0x7A,
                                    0x7A,0x78,0x77,0x76,0x72,0x19,0x18,0x17,0x16,0x14,0x13,0x71,0x70,0x6F,0x6E,0x6D,
                                    0x57,0x56,0x54,0x53,0x51,0x50,0x4E,0x4D,0x4B,0x4A,0x48,0x47,0x45,0x44,0x42,0x41,
                                    0x57,0x59,0x5A,0x5C,0x5D,0x5E,0x60,0x61,0x62,0x64,0x65,0x66,0x67,0x68,0x6A,0x6B,
                                    0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x7D,0x7D,0x7D,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,
                                    0x1A,0x1C,0x1D,0x1E,0x20,0x21,0x22,0x24,0x25,0x12,0x13,0x14,0x16,0x17,0x18,0x19,
                                    0x27,0x25,0x24,0x22,0x75,0x75,0x79,0x78,0x74,0x73,0x21,0x20,0x1E,0x1D,0x1C,0x1A,
                                    0x04,0x04,0x03,0x00,0x00,0x00,0x48,0x4A,0x4B,0x4D,0x4E,0x50,0x51,0x53,0x54,0x56,
                                    0x27,0x28,0x2A,0x3A,0x3C,0x3D,0x2B,0x2D,0x2E,0x34,0x36,0x37,0x39,0x30,0x31,0x33,
                                    0x3F,0x6C,0x6B,0x6A,0x68,0x67,0x3D,0x3C,0x3A,0x39,0x37,0x66,0x65,0x64,0x62,0x61};

const uint8_t xor_cipher_DR5XX0[0x100]={
                                    0x3F,0x41,0x42,0x44,0x45,0x47,0x48,0x4A,0x4B,0x4D,0x4E,0x50,0x51,0x53,0x54,0x56,
                                    0x57,0x59,0x5A,0x5C,0x5D,0x5E,0x60,0x61,0x62,0x64,0x65,0x66,0x67,0x68,0x6A,0x6B,
                                    0x6C,0x6D,0x6E,0x6F,0x70,0x71,0x72,0x73,0x74,0x75,0x75,0x76,0x77,0x78,0x78,0x79,
                                    0x7A,0x7A,0x7B,0x7B,0x7C,0x7C,0x7D,0x7D,0x7D,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,
                                    0x7F,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,0x7E,0x7D,0x7D,0x7D,0x7C,0x7C,0x7B,0x7B,0x7A,
                                    0x7A,0x79,0x78,0x78,0x77,0x76,0x75,0x75,0x74,0x73,0x72,0x71,0x70,0x6F,0x6E,0x6D,
                                    0x6C,0x6B,0x6A,0x68,0x67,0x66,0x65,0x64,0x62,0x61,0x60,0x5E,0x5D,0x5C,0x5A,0x59,
                                    0x57,0x56,0x54,0x53,0x51,0x50,0x4E,0x4D,0x4B,0x4A,0x48,0x47,0x45,0x44,0x42,0x41,
                                    0x3F,0x3D,0x3C,0x3A,0x39,0x37,0x36,0x34,0x33,0x31,0x30,0x2E,0x2D,0x2B,0x2A,0x28,
                                    0x27,0x25,0x24,0x22,0x21,0x20,0x1E,0x1D,0x1C,0x1A,0x19,0x18,0x17,0x16,0x14,0x13,
                                    0x12,0x11,0x10,0x0F,0x0E,0x0D,0x0C,0x0B,0x0A,0x09,0x09,0x08,0x07,0x06,0x06,0x05,
                                    0x04,0x04,0x03,0x03,0x02,0x02,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x02,0x02,0x03,0x03,0x04,
                                    0x04,0x05,0x06,0x06,0x07,0x08,0x09,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,
                                    0x12,0x13,0x14,0x16,0x17,0x18,0x19,0x1A,0x1C,0x1D,0x1E,0x20,0x21,0x22,0x24,0x25,
                                    0x27,0x28,0x2A,0x2B,0x2D,0x2E,0x30,0x31,0x33,0x34,0x36,0x37,0x39,0x3A,0x3C,0x3D};



void print_header_info(CS800D_header *h)
{
    printf("Header Information -\n");
    printf("\timage size - %08X\n", h->imagesize);
    printf("\timage header size - %08X\n", h->imageHeaderSize);
    printf("\tbase address offset %08X\n", h->baseaddr_offset);
    printf("\tresource header size - %02X\n", h->rsrcHeaderSize);
    printf("\tresource size - %08X\n", h->rsrc_size);
    printf("\tversion - %d\n", h->version);
}

int main(int argc, char** argv)
{
    char *flashfile = NULL;
    char *flashout = NULL;
    printf("Connect Systems Firmware Tool | by KG5RKI\n");

    if(sizeof(CS800D_header)!=0x80){
        printf("INTERNAL ERR FAILED CS800D_header size assertion - %02X", (uint32_t)sizeof(CS800D_header));
        return 1;
    }

    if(argc==1){
        print_usage();
        exit(0);
    }


    int fencrypt=0;
    int fdecrypt=0;
    int frsrc=0;
    int baseaddr=0x20000;
    int keysel=1;

    CS800D_header hdr;
    memset(&hdr, 0, sizeof(CS800D_header));

    for(int i = 1; i < argc; i++) {
        char *opt = argv[i];
        char *arg = (i == argc - 1) ? NULL : argv[i + 1];

        if(opt[0] != '-') {
            printf("error: invalid argument syntax!\n");
            return 1;
        }
        if(opt[0] == '-') { opt++; }
        if(opt[0] == '-') { opt++; }
        
        if(opt[0] == 'h' || !strcmp(opt, "help")) {
            print_usage();
            return 1;
        } else if(opt[0] == 'e' || !strcmp(opt, "encrypt")) {
            fencrypt = 1;
            if(fdecrypt) {
                printf("error: cannot decrypt and encrypt!\n");
                return 1;
            }
        } else if(opt[0] == 'd' || !strcmp(opt, "decrypt")) {
            fdecrypt = 1;
            if(fencrypt) {
                printf("error: cannot encrypt and decrypt!\n");
                return 1;
            }
        } else if(opt[0] == 'r' || !strcmp(opt, "resource")) {
            frsrc = 1;
            baseaddr=0;
        } else if(opt[0] == '1') {
            keysel=1;
        } else if(opt[0] == '2') {
            keysel=2;
        } else if(opt[0] == 'b' || !strcmp(opt, "base")) {
            if(!arg) {
                printf("error: invalid base address argument!\n");
                return 1;
            }
            if(frsrc){
                printf("error: resources don't have base address offsets\n");
                return 1;
            }
            baseaddr = atoi(arg);
            if(baseaddr>=0x08000000){
                if(baseaddr&0xFFF00000==0x08000000){
                    baseaddr-=0x08000000;
                }else{
                    printf("error: base address offset too high (remember to subtract 0x08000000)");
                    return 1;
                }
            }
            i++;
        } else if(opt[0] == 'i' || !strcmp(opt, "input")) {
            if(!arg) {
                printf("error: invalid flash input argument!\n");
                return 1;
            }
            flashfile = arg;
            i++;
        } else if(opt[0] == 'o' || !strcmp(opt, "output")) {
            if(!arg) {
                printf("error: invalid flash output argument!\n");
                return 1;
            }
            flashout = arg;
            i++;
        } else {
            printf("error: unknown option '%s'\n", opt);
            printf("try '%s --help' for more information\n", argv[0]);
            return 1;
        }
    }
    if(!flashfile || !flashout){
        printf("error: must specify input and output files\n");
        return 1;
    }


    FILE* fin = fopen(flashfile, "rb");
    if(!fin){
        printf("\nERR: Could not open %s", flashfile);
        return 1;
    }
    

    FILE* fout = fopen(flashout, "wb");
    if(!fout){
        printf("\nERR: Could not open %s", flashout);
        fclose(fin);
        return 1;
    }
    
    uint32_t fsize =0;
    fseek(fin, 0, SEEK_END);
    fsize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if(fdecrypt){
        fread(&hdr, 1, sizeof(CS800D_header), fin);

    }else if(fencrypt){
        
        if(frsrc){
            hdr.rsrcHeaderSize=sizeof(CS800D_header);
            hdr.imageHeaderSize=0;
            hdr.imagesize=0;
            hdr.rsrc_size=fsize;
            hdr.baseaddr_offset=0;
            hdr.version=1;
        }else{
            hdr.imageHeaderSize=sizeof(CS800D_header);
            hdr.rsrcHeaderSize=0;
            hdr.imagesize=fsize;
            hdr.rsrc_size=0;
            hdr.baseaddr_offset = baseaddr;
            hdr.version=1;
        }
        fwrite(&hdr, 1, sizeof(CS800D_header), fout);
    }
    print_header_info(&hdr);

    if(keysel<1 || keysel>2) keysel=1;

    if(keysel==1){
        printf("Using CS800 cipher\n");
    }else if(keysel==2){
        printf("Using DR5XX0 cipher\n");
    }

    printf("\n");
    uint8_t a=0,b=0,c=0;
    uint32_t xor_ctr=0;
    for(int i=0; (i<fsize && fencrypt) || (i<(fsize-0x80) && fdecrypt); i++){
        fread(&a, 1, 1, fin);
        
        if(keysel==1)
            b = xor_cipher_CS800[xor_ctr];
        else if(keysel==2)
            b = xor_cipher_DR5XX0[xor_ctr];
        
        c = a ^ b;
        xor_ctr++;
        if(xor_ctr>=0x100){
            xor_ctr=0;
        }

        fwrite(&c, 1, 1, fout);
        fflush(fout);
        
        fprintf(stdout, "\r%s:  %d", (fencrypt ? "Encrypting" : "Decrypting"), (int)(((float)i/(float)fsize)*100.0f) );
        fflush(stdout);
    }

    fflush(fout);
    fclose(fout);
    fclose(fin);
    printf("\r\nDone! Written to %s\n", flashout);

    return 0;
}