/*
 * 2005-04-30 ysato@delegate.org
 * maybe the most naive implementation of stab generator for "dl"
 *
 * Input:
 *   // BEGIN_STAB(libname)
 *   Type name(arglist);
 *   // END_STAB
 *
 * Output:
 *   1. Type (*name_PTR_)(arglist);
 *   2. #define name (*name_PTR_)
 *   3. DLTab dltab_libname[] = {
 *        {"name", &name_PTR_},
 *        0,
 *      };
 */
#ifndef UNDER_CE
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(int ac,char *av[]){
	char line[1024];
	char type[128];
	char type1[128];
	char name[128];
	char ch;
	const char *sp;
	char *tp;
	char *ep;
	char *np;
	char *names[256];
	char *op;
	char *opts[256];
	const char *name1;
	int namex = 0;
	int i;
	int dorw = 0;
	char libname[32];
	char opt[128];
	int skip = 0;
	int lni,lno;

	libname[0] = 0;
	lni = lno = 0;
	for(;;){
		if( lni != lno ){
			printf("#line %d\n",lni+1);
			lno = lni;
		}
		if( fgets(line,sizeof(line),stdin) == NULL )
			break;
		lni++;

		if( skip ){
			if( strncmp(line,"#endif",6) == 0
			 || strncmp(line,"#else",5) == 0
			){
				skip = 0;
			}else{
				printf("\n");
				lno++;
				continue;
			}
		}
		if( strncmp(line,"#ifdef _MSC_VER",15) == 0 ){
#ifdef _MSC_VER
#else
			skip = 1;
#endif
		}

printf("%s",line);
lno++;
		if( sp = strstr(line,"/*BEGIN_STAB") ){
			if( sp[12] == '(' ){
				sscanf(sp+13,"%[^)]",libname);
			}
			dorw = 1;
printf("#include <stdio.h> /*DLST*/\n");
printf("#define PCStr(s) const char *s /*DLST*/\n");
printf("#define ISDLIB /*DLST*/\n");
printf("/*DLST*/ typedef struct {const char*name; void*addr; const char*opt;} DLMap;\n");
printf("/*DLST*/ extern DLMap dlmap_%s[];\n",libname);
printf("/*DLST*/ void *dgdlsym(DLMap*,const char *sym);\n");
printf("#define mydlsym(s) dgdlsym(dlmap_%s,s)\n",libname);
lno += 7;
		}else
		if( strstr(line,"/*END_STAB*/") ){
			dorw = 0;
		}
		if( dorw == 0 )
			continue;

		sp = line;
		tp = type;
		ep = type;
		np = name;
		type[0] = 0;
		name[0] = 0;
		for( sp = line; ch = *sp; sp++ ){
			if( isalnum(ch) || ch == '_' )
				break;
		}
		while( ch = *sp ){
			if( !isspace(ch) && !isalnum(ch) && ch != '_'
			 && ch != '*' && ch != '(' )
				break;
			if( ch == '(' )
				break;
			if( !isalnum(ch) && ch != '_' ){
				np = name;
				ep = tp+1;
			}else{
				*np++ = ch;
			}
			if( tp == type && isspace(ch) ){
			}else{
				*tp++ = ch;
			}
			sp++;
		}
		if( ch != '(' ){
			continue;
		}
		if( np == name ){
			continue;
		}
		if( strstr(sp,");") == 0 ){
			continue;
		}
		*tp = 0; *ep = 0;
		*np = 0;
		while( type < ep ){
			if( isspace(ep[-1]) )
				ep--;
			else	break;
		}
		*ep = 0;
		if( type[0] == 0 )
			continue;

		sscanf(type,"%s",type1);
		if( strcmp(type1,"typedef") == 0
		 || strcmp(type1,"sizeof") == 0
		 || strcmp(type1,"return") == 0
		 || strcmp(type1,"else") == 0
		)
			continue;

printf("/*DLST*/ %s",line);
printf("/*DLST*/ %s (*%s_PTR_)%s",type,name,sp);
printf("#define %s (*%s_PTR_) /*DLST*/\n",name,name);
lno += 3;
		if( op = strstr(line,"/*OPT(") ){
			opt[0] = 0;
			sscanf(op+6,"%[^)]",opt);
			opts[namex] = strdup(opt);
		}else	opts[namex] = 0;
		names[namex++] = strdup(name);
	}
	names[namex] = 0;

printf("/*DLST*/ DLMap dlmap_%s[] = {\n",libname);
printf("/*DLST*/ {\"#%s\"}, /*handle*/\n",libname);
	for( i = 0; i < namex; i++ ){
		name1 = names[i];
if( opts[i] )
printf("/*DLST*/ {\"%s\",&%s_PTR_,\"%s\"},\n",name1,name1,opts[i]);
else
printf("/*DLST*/ {\"%s\",&%s_PTR_},\n",name1,name1);
	}
printf("/*DLST*/ 0};\n");
	return 0;
}
#endif
