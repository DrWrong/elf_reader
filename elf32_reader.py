#!/usr/bin/python3.3m
# -*- coding: utf-8 -*-
#
#  elf32_reader.py
# 功能读取 elf 文件的表
#  用法 python3.3m elf32_reader.py elf文件名
#  eg python3.3m a.out
#  

import struct
from sys import argv,stderr
#typedef struct
#{
#  unsigned char	e_ident[EI_NIDENT];	/* Magic number and other info */
#  Elf32_Half 	e_type;			/* Object file type */
#  Elf32_Half	e_machine;		/* Architecture */
#  Elf32_Word	e_version;		/* Object file version */
#  Elf32_Addr	e_entry;		/* Entry point virtual address */
#  Elf32_Off	e_phoff;		/* Program header table file offset */
#  Elf32_Off	e_shoff;		/* Section header table file offset */
#  Elf32_Word	e_flags;		/* Processor-specific flags */
#  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
# Elf32_Half	e_phentsize;		/* Program header table entry size */
# Elf32_Half	e_phnum;		/* Program header table entry count */
#  Elf32_Half	e_shentsize;		/* Section header table entry size */
#  Elf32_Half	e_shnum;		/* Section header table entry count */
#  Elf32_Half	e_shstrndx;		/* Section header string table index */
#} Elf32_Ehdr;
#elf 32 头文件格工
Elf32_Ehdr_format="=16B2H5I6H"
#typedef struct
#{
#  Elf32_Word	sh_name;		/* Section name (string tbl index) */
#  Elf32_Word	sh_type;		/* Section type */
#  Elf32_Word	sh_flags;		/* Section flags */
#  Elf32_Addr	sh_addr;		/* Section virtual addr at execution */
#  Elf32_Off	sh_offset;		/* Section file offset */
#  Elf32_Word	sh_size;		/* Section size in bytes */
#  Elf32_Word	sh_link;		/* Link to another section */
#  Elf32_Word	sh_info;		/* Additional section information */
#  Elf32_Word	sh_addralign;		/* Section alignment */
#  Elf32_Word	sh_entsize;		/* Entry size if section holds table */
#} Elf32_Shdr;
Elf32_Shdr_format="=10I"
#typedef struct
#{
#  Elf32_Word	p_type;			/* Segment type */
#  Elf32_Off	p_offset;		/* Segment file offset */
#  Elf32_Addr	p_vaddr;		/* Segment virtual address */
#  Elf32_Addr	p_paddr;		/* Segment physical address */
#  Elf32_Word	p_filesz;		/* Segment size in file */
#  Elf32_Word	p_memsz;		/* Segment size in memory */
#  Elf32_Word	p_flags;		/* Segment flags */
#  Elf32_Word	p_align;		/* Segment alignment */
#} Elf32_Phdr;
Elf32_Phdr_format='=8I'
def main():
	filename=argv[1]
	file=open(filename,'rb')
	elf32_header=struct.unpack(Elf32_Ehdr_format,file.read(struct.calcsize(Elf32_Ehdr_format)))
	
	print ("ELF头：")
	Magic=""
	for each_magic in elf32_header[0:16]:
		Magic+='%02x '%each_magic
	print (" Magic:    ",Magic)
	# 读取e_ident[4] 文件类型
	if elf32_header[4]==1:
		Class="ELF32"
	elif elf32_header[4]==2:
		Class="ELF64"
	else:
		print("非法的类别",file=stderr)
		exit(1)
	print ("Class: ",Class)
	# 读取e_ident[5] 编码方式
	if elf32_header[5]==1:
		Data="2's complement,little endian"
	elif elf32_header[5]==2:
		Data="2's complement,little endian"
	else:
		print("非法数据编码",file=stderr)
		exit(1)
	print ("Data:  ",Data)
	#读取e_ident[6] 版本
	if elf32_header[6]==1:
		version='1(current)'
	else:
		print("非法版本号",file=stderr)
		exit(1)
	print("Version:  ",version)
	#读取e_ident[7] OS ABI
	osAbi={0:'UNIX-System V',1:'HP-UX',2:'NetBSD',3:'GNU/Linux',\
	6:'Solaris',7:'IBM AIX',8:'SGI Irix',9:'FreeBSD',\
	10:'Compaq Tru64 unix',11:'Novell Modesto',12:'OpenBSD',\
	64:'ARM EABI',97:'ARM',255:'Standalone'}
	print("OS/ABI:",osAbi[elf32_header[7]])
	#ABI version
	print ("ABI Version:  ",str(elf32_header[8]))
	Type=['未知目标文件格式','可重定位文件','可执行文件','共享目标文件','Core文件']
	print("Type:    ",Type[elf32_header[16]])
	machine=['undefine','AT&T WE 32100','SPARC','Intel 80386','Motorla 68000',\
	'Motorola 88000','Intel 80860','MIPS RS3000','others']
	print('Machine:  ',machine[elf32_header[17]])
	print ('Version:   %#x'%elf32_header[18])
	print('入口点地址：   %#x'%elf32_header[19])
	print('程序头起点：   %d(bytes into file)'%elf32_header[20])
	print('Start of section headers:   %d(bytes into file)'%elf32_header[21])
	print ('标志：   %#x'%elf32_header[22])
	#ELF头大小  所有的头应该一样吧？ 进地校验吗？
	print('本头的大小： %d(字节）'%elf32_header[23])
	#所有程序头部表格的表项大小 大小一致
	print ('程序头大小：%d(字节）'%elf32_header[24])
	print ('Number of program headers:   %d'%elf32_header[25])
	print ('节头大小： %d(字节）'%elf32_header[26])
	print ('节头数量： %d'%elf32_header[27])
	print ('字符串表索引节头： %d'%elf32_header[28])
	#读取节区头部表
	print('节头：')
	print('[Nr]    Name        Type        Addr        Off        Size  \
	ES    Flg  LK  Inf Al')
	file.seek(elf32_header[21])
	elf32_sheaders=[]
	for i in range(elf32_header[27]):
		elf32_sheaders.append(struct.unpack(Elf32_Shdr_format,file.read(struct.calcsize(Elf32_Shdr_format))))
	secgroup=[]
	symtable=[]
	section_name=[]
	dynamic=[]
	rel_section=[]
	for i in range(elf32_header[27]):
		print('[%2d]'%i,end=' ')
		sh_name=''
		offset=elf32_sheaders[elf32_header[28]][4]+elf32_sheaders[i][0]
		file.seek(offset,0)
		while True:
			
			ch=struct.unpack('=c',file.read(1))
			if ch[0].decode('ascii')!='\0':
				sh_name+=ch[0].decode('ascii')
			else:
				break
		print("%-20s"%sh_name,end=' ')
		section_name.append(sh_name)
		sh_type={0:'NULL',1:'program data',2:'Symbol table',3:'String table',4:'Relocation entries',\
		5:'Symbol hash table',6:'Dynamic linking information',7:'Notes',\
		8:'Program space with no data(bbs)',9:'Relocation entries',10:'Reserved',\
		11:'Dynamic linker symbol table', 14:'Array of constructors',15:'Arrsy of destructors',\
		16:'Array of pre-constructors',17:'Section group',18:'Extended section indeces',\
		19:'Number of defined types',0x60000000:'Start OS-specific', 0x6ffffff5:'Object attributes',\
		0x6ffffff6:'GNU-style hash table',0x6ffffff7:'Prelink library list',\
		0x6ffffff8:'Checksum for DSO content',0x6ffffffa:'Sun-specific low bound',\
		0x6ffffffb:'Version definition section',0x6ffffffc:'Version definition section',\
		0x6ffffffd:'Version definition section',0x6ffffffe:'Version needs section',\
		0x6fffffff:'Version symbol table', 0x70000000:'Start of proceessor-specific',\
		0x7fffffff:'End of proceesor-specific',0x80000000:'Start of application-specific',\
		0x8fffffff:'End of application-specific'}
		print('%-30s'%sh_type[elf32_sheaders[i][1]],end=' ')
		if elf32_sheaders[i][1]==17:
			secgroup.append(i)
		if elf32_sheaders[i][1] in [2,11]:
			symtable.append((elf32_sheaders[i],i))
		if elf32_sheaders[i][1]==6:
			dynamic.append(elf32_sheaders[i])
		if elf32_sheaders[i][1]==9:
			rel_section.append((elf32_sheaders[i],i,9))
		if elf32_sheaders[i][1]==4:
			rel_section.append((elf32_sheaders[i],i,4))
		print("%08x  "%elf32_sheaders[i][3],end=' ')
		print ("%06x  "%elf32_sheaders[i][4],end=' ')
		print ("%06x  "%elf32_sheaders[i][5],end=' ')
		print("%02x  "%elf32_sheaders[i][9],end=' ')
		flg=''
		if elf32_sheaders[i][2]&(1<<0):
			flg+='W'
		if elf32_sheaders[i][2]&(1<<1):
			flg+='A'
		if elf32_sheaders[i][2]&(1<<2):
			flg+='X'
		if elf32_sheaders[i][2]&(1<<4):
			flg+='M'
		if elf32_sheaders[i][2]&(1<<5):
			flg+='S'
		if elf32_sheaders[i][2]&(1<<6):
			flg+='I'
		if elf32_sheaders[i][2]&(1<<7):
			flg+='L'
		if elf32_sheaders[i][2]&(1<<9):
			flg+='G'
		if elf32_sheaders[i][2]&(1<<10):
			flg+='T'
		if elf32_sheaders[i][2]&(1<<31):
			flg+='E'
		if elf32_sheaders[i][2]&(1<<8):
			flg+='O'
		if elf32_sheaders[i][2]==0x0ff00000:
			flg+='o'
		if elf32_sheaders[i][2]==0xf0000000:
			flg+='p'
		if elf32_sheaders[i][2]!=0 and flg=='':
			flg+='x'
		print('%-4s'%flg,end=' ')
		print('%-d   '%elf32_sheaders[i][6],end=' ')
		print('%-d   '%elf32_sheaders[i][7],end=' ')
		print('%-d'%elf32_sheaders[i][8])
	print('Key to Flags:')
	print( '''W(write),A(alloc),X(execute),M(merge),s(strings)
	I(info),L(link order),G(group),T(TLS),E(exclude),x(unknown)
	O(extra OS processing required) o(OS specific),p(processor specific''')	
	if len(secgroup)==0:
		print('There are no section groups in this file')
	else:
		#目前不知道如何处理！！！
		print('目前不知道如何处理！！！')
	#读取程序头
	print('程序头：')
	print('%-12s%-10s%-10s%-10s%-10s%-10s%-4s%-8s'%('Type','Offset','VirtAddr',\
	'PhysAddr','FileSiz','MemSiz','Flg','Align'))
	file.seek(elf32_header[20])
	elf32_phdrs=[]
	
	for i in range(elf32_header[25]):
		elf32_phdrs.append(struct.unpack(Elf32_Phdr_format,file.read(struct.calcsize(Elf32_Phdr_format))))
	for i in range(elf32_header[25]):
		#读取type
		p_types={0:'NULL',1:'LOAD',2:'DYNAMIC',3:'INTERP',4:'NOTE',5:'SHLIB',\
		6:'PHDR',7:'TLS',8:'NUM',0x60000000:'LOOS',0x6474e550:'GUN_EH_FRAME',\
		0x6474e551:'GNU_STACK',0x6474e552:'GNU_RELRO',0x6ffffffa:'Sun specific',\
		0x6ffffffb:'SUNWSTACK',0x6fffffff:'HIOS',0x70000000:'LOPROC',0x7fffffff:'HIPROC'}
		print("%-12s"%p_types[elf32_phdrs[i][0]],end=' ')
		
		print("%#08x  "%elf32_phdrs[i][1],end=' ')
		print("%#08x  "%elf32_phdrs[i][2],end=' ')
		print('%#08x  '%elf32_phdrs[i][3],end=' ')
		print('%#08x  '%elf32_phdrs[i][4],end=' ')
		print('%#08x  '%elf32_phdrs[i][5],end=' ')
		flg=''
		if elf32_phdrs[i][6]&(1<<2):
			flg+='R'
		if elf32_phdrs[i][6]&(1<<1):
			flg+='W'
		if elf32_phdrs[i][6]&(1<<0):
			flg+='E'
		if elf32_phdrs[i][6]==0x0ff00000:
			flg+='O'
		if elf32_phdrs[i][6]==0xf0000000:
			flg+='P'
		print('%-4s'%flg,end=' ')
		print('%-#x'%elf32_phdrs[i][7])
	print('Section to Segment mapping:')
	print('段节：')
	for i in range(elf32_header[25]):
		print('{:02d}   '.format(i),end=' ')
		sections=''
		for j in range(elf32_header[27]):
			if elf32_sheaders[j][4]>=elf32_phdrs[i][1] and elf32_sheaders[j][4]<(elf32_phdrs[i][1]+elf32_phdrs[i][4]):
				sections+=' '+section_name[j]
		print(sections)
	if len(dynamic)==0:
		print('No Dynamic section found')
	else:
		dynamic_format='=II'
		for eachentry in dynamic:
			dynamic_table=[]
			dynamic_sections=[]
			file.seek(eachentry[4])
			while True:
				dynamic_section=struct.unpack(dynamic_format,file.read(struct.calcsize(dynamic_format)))
				dynamic_sections.append(dynamic_section)
				if dynamic_section[0]==0:
					break
			for dynamic_section in dynamic_sections:
				dynamic_entry=[]
				dynamic_entry.append(dynamic_section[0])
				dynamic_type={0:'NULL',1:'NEEDED',2:'PLTRELSZ',3:'PLTGOT',4:'HASH',\
				5:'STRTAB',6:'SYMTAB',7:'RELA',8:'RELASZ',9:'RELAENT',10:'STRSZ',11:'SYMENT',\
				12:'INIT',13:'FINT',14:'SONAME',15:'RPATH',16:'SYMBOLIC',17:'REL',\
				18:'RELSZ',19:'RELENT',20:'PLTREL',21:'DEBUG',22:'TEXTREL',23:'JMPREL',\
				24:'BIND_NOW',25:'INIT_ARRAY',26:'FINT_ARRAY',27:'INITARRAYSZ',28:'FINT_ARRAYSZ',\
				29:'RUNPATH',30:'FLAGS',32:'ENCODING',33:'PREINIT_ARRAYSZ',34:'NUM',0x6000000d:'LOOPS',\
				0x6ffff000:'HIOS',0x70000000:'LOPROC',0x7fffffff:'HIPROC',0x6ffffd00:'VALRNGLO',\
				0x6ffffdf5:'PRELINKED',0x6ffffdf6:'CONFLISTSZ',0x6ffffdf7:'LIBLISTSZ',\
				0x6ffffdf8:'CHECKSUM',0x6ffffdf9:'PLTPADSZ',0x6ffffdfa:'MOVEENT',\
				0x6ffffdfb:'MOVESZ',0x6ffffdfc:'FEATURE_1',0x6ffffdfd:'POSFLAG_1',\
				0x6ffffdfe:'SYMINSZ',0x6ffffdff:'SYMINENT',0x6ffffe00:'ADDRRNGLO',\
				0x6ffffef5:'GUN_HASH',0x6ffffef6:'TLSDESC_PLT',0x6ffffef7:'TLSDESC_GOT',\
				0x6ffffdf8:'GNU_CONFLICT',0x6ffffef9:'GNU_LIBLIST',\
				0x6ffffefa:'CONFIG',0x6ffffefb:'DEPAUDIT',0x6ffffefc:'AUDIT',\
				0x6ffffefd:'PLTPAD',0x6ffffefe:'MOVETAB',0x6ffffeff:'SYMINFO',\
				0x6ffffff0:'VERSYM',0x6ffffffa:'RELCOUNT',0x6fffffb:'FLAGS_1',\
				0x6ffffffc:'VERDEF',0x6ffffffd:'VERDEFNUM',0x6fffffff:'VERNEEDNUM',\
				0x7ffffffd:'AUXILIARY',0x7fffffff:'FILTER'}
				try:
					dynamic_entry.append('('+dynamic_type[dynamic_section[0]]+')')
				except:
					dynamic_entry.append('('+'%#x'%dynamic_section[0]+')')
				d_tag=dynamic_section[0]
				if d_tag in [0,3,4,5,6,7,12,13,15]:
					dynamic_entry.append('%#x'%dynamic_section[1])
				elif d_tag==1:
					file.seek(elf32_sheaders[eachentry[6]][4]+dynamic_section[1])
					lib_name=''
					while True:
						ch=struct.unpack('=c',file.read(1))
						if ch[0].decode('ascii')!='\0':
							lib_name+=ch[0].decode('ascii')
						else:
							break
					dynamic_entry.append('共享库：['+lib_name+']')
				elif d_tag in [2,8,9,10,11,18,19]:
					dynamic_entry.append('%d (bytes)'%dynamic_section[1])
				elif d_tag==14:
					file.seek(elf32_sheaders[eachentry[6]][4]+dynamic_section[1])
					lib_name=''
					while True:
						ch=struct.unpack('=c',file.read(1))
						if ch[0].decode('ascii')!='\0':
							lib_name+=ch[0].decode('ascii')
						else:
							break
					dynamic_entry.append('Library soname:['+lib_name+']')
				else:
					dynamic_entry.append('不清楚此节区%#x'%dynamic_section[1] )
				dynamic_table.append(dynamic_entry)
				
			print('Dynamic section at offset %#x contains %d entries:'%(eachentry[4],len(dynamic_table)))
			print('{0:^10}{1:^20}{2:^10}'.format('标记','类型',"名称/值"))
			for eachentry in dynamic_table:
				print('%#010x %-12s %-20s'%(eachentry[0],eachentry[1],eachentry[2]))
	if len(rel_section)==0:
		print('未发现重定位节。')
	else:
		for eachentry,i,n in rel_section:
			print("重定位节'%s'位于偏移量 %#x 含有 %d 个条目："%(section_name[i],eachentry[4],int(eachentry[5]/eachentry[9])))
			print('{0:^10}{1:^10}{2:^20}{3:^20}{4:^30}'.format('Offset','Info','Type','Sym.Value','Sym.Name'))
			if n==9:
				rel_format='=2I'
			elif n==4:
				rel_format='=3I'
			file.seek(eachentry[4])
			rel_sections=[]
			for i in range(int(eachentry[5]/eachentry[9])):
				rel_section=struct.unpack(rel_format,file.read(struct.calcsize(rel_format)))
				rel_sections.append(rel_section)
			for rel_section in rel_sections:
				print('%08x'%rel_section[0],end='  ')
				print('%08x'%rel_section[1],end='  ')
				rel_types=['R_386_NONE','R_386_32','R_386_PC32',\
				'R_386_GOT32','R_386_PLT32','R_386_COPY',\
				'R_386_GLOB_DAT','R_386_JMP_SLOT','R_386_RELATIVE',\
				'R_386_GOTOFF','R_386_GOTPC']
				print('%-20s'%rel_types[rel_section[1]&0xff],end='  ')
				file.seek(elf32_sheaders[eachentry[6]][4]+(rel_section[1]>>8)*elf32_sheaders[eachentry[6]][9])
				sym=struct.unpack('=3I2BH',file.read(struct.calcsize('=3I2BH')))
				print('%08x'%sym[1],end='  ')
				file.seek(elf32_sheaders[elf32_sheaders[eachentry[6]][6]][4]+sym[0])
				sym_name=''
				while True:
					ch=struct.unpack('=c',file.read(1))
					if ch[0].decode('ascii')!='\0':
						sym_name+=ch[0].decode('ascii')
					else:
						break;
				print('%-20s'%sym_name)
	if len(symtable)==0:
		print('未发现符号表')
	else:
		for eachentry,i in symtable:
			print("Symbol table '%s' contains %d entries:"%(section_name[i],int(eachentry[5]/eachentry[9])))
			print('  Num:    Value:  Size  Type    Bind    Vis   Ndx  Name')
			file.seek(eachentry[4])
			symentrys=[]
			for i in range(int(eachentry[5]/eachentry[9])):
				symentrys.append(struct.unpack('=3I2BH',file.read(struct.calcsize('=3I2BH'))))
			i=0
			for symentry in symentrys:
				print('%4d'%i,end=' ')
				print('%08x'%symentry[1],end=' ')
				print('%4d'%symentry[2],end=' ')
				symtypes={0:'NOTYPE',1:'OBJECT',2:'FUNC',3:'SECTION',4:'FILE',5:'COMMON',\
				6:'TLS',7:'NUM',10:'LOOS',12:'HIOS',13:'LOPROC',15:'HIPROC'}
				print("-%8s"%symtypes[symentry[3]&0xf],end=' ')
				binds={0:'LOCAL',1:'GLOBAL',2:'WEAK',3:'NUM',10:'LOOS',12:'HIOS',13:'LOPROC',15:'HIPROC'}
				print('%-8s'%binds[symentry[3]>>4],end=' ')
				viss=['DEFAULT','INTERNAL','HIDDEN','RPOTECTED']
				print('%-8s'%viss[symentry[4]&0x03],end=' ')
				if symentry[5]==0:
					print('UND',end=' ')
				else:
					print('%3d'%symentry[5],end=' ')
				file.seek(elf32_sheaders[eachentry[6]][4]+symentry[0])
				sym_name=''
				while True:
					ch=struct.unpack('=c',file.read(1))
					if ch[0].decode('ascii')!='\0':
						sym_name+=ch[0].decode('ascii')
					else:
						break;
				print('%-20s'%sym_name)
				
	file.close()   
	return 0

if __name__ == '__main__':
	main()

