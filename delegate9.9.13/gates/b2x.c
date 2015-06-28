#include <stdio.h>
#include <string.h>
#include <fcntl.h>

int main(int ac, char *av[]){
	int ai;
	int opt_rev = 0;
	char *ifile = 0;
	char *ofile = 0;
	char ofileb[256];
	FILE *in,*out;

#ifdef O_BINARY
	extern int _fmode;
	_fmode = O_BINARY;
#endif
	for( ai = 1; ai < ac; ai++ ){
		if( strcmp(av[ai],"-r") == 0 ){
			opt_rev = 1;
			continue;
		}
		if( ifile == 0 )
			ifile = av[ai];
		else	ofile = av[ai];
	}
	if( ifile == 0 || strcmp(ifile,"-") == 0 ){
		in = stdin;
		ifile = "-";
	}else{
		in = fopen(ifile,"r");
		if( in == NULL ){
			fprintf(stderr,"-- b2x: cannot open infile: %s\n",ifile);
			return -1;
		}
	}
	if( ofile != NULL && strcmp(ofile,"-") == 0 ){
		out = stdout;
	}else{
		if( ofile == 0 ){
			if( strcmp(ifile,"-") == 0 ){
				ofile = "-";
			}else{
				char *op;
				strcpy(ofileb,ifile);
				if( (op = strrchr(ofileb,'.')) == 0 )
					op = ofileb + strlen(ofileb);
				if( opt_rev )
					strcpy(op,".o");
				else	strcpy(op,".ox");
				ofile = ofileb;
			}
		}
		if( strcmp(ofile,"-") == 0 ){
			out = stdout;
		}else{
			out = fopen(ofile,"w");
			if( out == NULL ){
				fprintf(stderr,"-- b2x: cannot open outfile: %s\n",ofile);
				return -1;
			}
		}
	}
	fprintf(stderr,"-- b2x: '%s' -> '%s'\n",ifile,ofile);

	if( opt_rev ){
		char buf[3];
		int ch1,ch2,xch;

		buf[2] = 0;
		for(;;){
			ch1 = getc(in);
			if( ch1 == '\n' )
				ch1 = getc(in);
			ch2 = getc(in);
			if( ch1 == EOF || ch2 == EOF )
				break;
			buf[0] = ch1;
			buf[1] = ch2;
			xch = -1;
			sscanf(buf,"%X",&xch);
			if( xch < 0 || 0x100 <= xch ){
				fprintf(stderr,"-- b2x: broken input: %02X %02X %s\n",
					ch1,ch2,ifile);
				break;
			} 
			putc(xch,out);
		}
	}else{
		int ch;
		int cols;
		cols = 0;
		while( (ch = getc(in)) != EOF ){
			fprintf(out,"%02X",ch);
			cols += 2;
			if( 72 < cols ){
				fprintf(out,"\n");
				cols = 0;
			}
		}
		fprintf(out,"\n");
	}
	return 0;
}
