//https://frida.re/docs/javascript-api
//https://github.com/actboy168/YDWE/blob/39b18198c784b589a944cb61220340541dcbf8bb/OpenSource/stormdll.txt
//http://jass.sourceforge.net/doc/api/common_j-functions.shtml
//http://jass.sourceforge.net/doc/api/Blizzard_j-source.shtml#2613
//https://github.com/actboy168/YDWE/blob/39b18198c784b589a944cb61220340541dcbf8bb/Development/Core/ydwar3/warcraft3/hashtable.h

/*
frida -p (ps War3).id -l aa.py.js


		
*/

const VirtualAlloc = new NativeFunction(Module.findExportByName(null,"VirtualAlloc"), 'pointer', ['pointer', 'size_t', 'uint32', 'uint32']);
var GameDll = Module.findBaseAddress('Game.dll')

function readExeVersion(filePath) {
    const kernel32 = Module.load('kernel32.dll');
    const versionDll = Module.load('version.dll');
    
    const GetFileVersionInfoSizeW = new NativeFunction(
        versionDll.getExportByName('GetFileVersionInfoSizeW'),
        'uint32', ['pointer', 'pointer']
    );

    const GetFileVersionInfoW = new NativeFunction(
        versionDll.getExportByName('GetFileVersionInfoW'),
        'bool', ['pointer', 'uint32', 'uint32', 'pointer']
    );

    const VerQueryValueW = new NativeFunction(
        versionDll.getExportByName('VerQueryValueW'),
        'bool', ['pointer', 'pointer', 'pointer', 'pointer']
    );

    const filePathW = Memory.allocUtf16String(filePath);
    const dummy = Memory.alloc(Process.pointerSize);
    const versionSize = GetFileVersionInfoSizeW(filePathW, dummy);

    if (versionSize === 0) {
        console.log('Failed to get version size.');
        return null;
    }

    const versionInfo = Memory.alloc(versionSize);
    if (!GetFileVersionInfoW(filePathW, 0, versionSize, versionInfo)) {
        console.log('Failed to get version info.');
        return null;
    }

    const lplpBuffer = Memory.alloc(Process.pointerSize);
    const puLen = Memory.alloc(Process.pointerSize);
    const subBlock = Memory.allocUtf16String('\\');

    if (!VerQueryValueW(versionInfo, subBlock, lplpBuffer, puLen)) {
        console.log('Failed to query version value.');
        return null;
    }

    const fixedFileInfo = lplpBuffer.readPointer();
    const fileVersionMS = fixedFileInfo.add(8).readU32();
    const fileVersionLS = fixedFileInfo.add(0xc).readU32();

    const version = [
        (fileVersionMS >>> 16) & 0xffff,
        (fileVersionMS >>> 0) & 0xffff,
        (fileVersionLS >>> 16) & 0xffff,
        (fileVersionLS >>> 0) & 0xffff
    ].join('.');

    return version;
}

if(readExeVersion(Process.mainModule.path)!='1.27.0.52240')
{
	console.error("仅支持版本【1.27.0.52240】")
}	

function dumpAddr(addr, size, showoffset = 0) {
	if (addr.isNull())
		return;
	const buf = addr.readByteArray(size);
	// If you want color magic, set ansi to true
	console.log(hexdump(buf, { offset: showoffset ? addr : 0, length: size, header: true, ansi: false }));
}
function hex2float(num) {
	const sign = (num & 0x80000000) ? -1 : 1;
	const exponent = ((num >> 23) & 0xff) - 127;
	const mantissa = 1 + ((num & 0x7fffff) / 0x7fffff);
	return (sign * mantissa * Math.pow(2, exponent)).toFixed(2);
}
function code2hex(code) {
	return (code.charCodeAt(0)<<24) +
	(code.charCodeAt(1)<<16) +
	(code.charCodeAt(2)<<8) +
	code.charCodeAt(3)
	//return Memory.allocAnsiString(code).readU32()
}
function hex2code(hex) {
	var mmoo = Memory.alloc(0x40)
	mmoo.writeU32(hex)
	return mmoo.readCString(4).split('').reverse().join('')
}
function float2Hex(num) {
	const view = new DataView(new ArrayBuffer(4))
	view.setFloat32(0, num)
	return view.getUint32() 
}
function createint(ss) {
	var mmoo = Memory.alloc(0x40)
	mmoo.writeU32(ss)
	return mmoo
}
function createfloat(ff) {	
	var mmoo = Memory.alloc(0x10)
	mmoo.writeU32(float2Hex(ff))
	return mmoo
}
function createString(ss) {
	if(ss==null ||ss==undefined) return ptr(0)
	var mmoo = Memory.alloc(0x200 + ss.length)
	mmoo.add(8).writePointer(mmoo.add(0x10))
	mmoo.add(0xc).writeU32(1)
	mmoo.add(0x10 + 0x1c).writePointer(mmoo.add(0x100))
	mmoo.add(0x100).writeUtf8String(ss)
	return mmoo
}
function disasm(p)
{
	for(let i=0;i<50;i++)
	{
		const line = Instruction.parse(p)
		console.log(p + " "+line.mnemonic +" "+line.opStr)
		p = line.next
	}
}

const OPCODE_VARIABLE = {
	NOTHING: 0,        // "nothing"
	UNKNOWN: 1,        // "unknown"
	NULL: 2,           // "null"
	CODE: 3,           // "code"
	INTEGER: 4,        // "integer"
	REAL: 5,           // "real"
	STRING: 6,         // "string"
	HANDLE: 7,         // "handle"
	BOOLEAN: 8,        // "boolean"
	INTEGER_ARRAY: 9,  // "integer array"
	REAL_ARRAY: 10,    // "real array"
	STRING_ARRAY: 11,  // "string array"
	HANDLE_ARRAY: 12,  // "handle array"
	BOOLEAN_ARRAY: 13  // "boolean array"
}
const UNIT_STATE = {
	// original
	UNIT_STATE_ATTACK1_DAMAGE_DICE          : 0x10,
	UNIT_STATE_ATTACK1_DAMAGE_SIDE          : 0x11,
	UNIT_STATE_ATTACK1_DAMAGE_BASE          : 0x12,
	UNIT_STATE_ATTACK1_DAMAGE_BONUS         : 0x13,
	UNIT_STATE_ATTACK1_DAMAGE_MIN           : 0x14,
	UNIT_STATE_ATTACK1_DAMAGE_MAX           : 0x15,
	UNIT_STATE_ATTACK1_RANGE                : 0x16,
	UNIT_STATE_ARMOR                        : 0x20,
	// attack 1 attribute adds
	UNIT_STATE_ATTACK1_DAMAGE_LOSS_FACTOR   : 0x21,
	UNIT_STATE_ATTACK1_WEAPON_SOUND         : 0x22,
	UNIT_STATE_ATTACK1_ATTACK_TYPE          : 0x23,
	UNIT_STATE_ATTACK1_MAX_TARGETS          : 0x24,
	UNIT_STATE_ATTACK1_INTERVAL             : 0x25,
	UNIT_STATE_ATTACK1_INITIAL_DELAY        : 0x26,
	UNIT_STATE_ATTACK1_BACK_SWING           : 0x28,
	UNIT_STATE_ATTACK1_RANGE_BUFFER         : 0x27,
	UNIT_STATE_ATTACK1_TARGET_TYPES         : 0x29,
	UNIT_STATE_ATTACK1_SPILL_DIST           : 0x56,
	UNIT_STATE_ATTACK1_SPILL_RADIUS         : 0x57,
	UNIT_STATE_ATTACK1_WEAPON_TYPE          : 0x58,
	// attack 2 attributes (sorted in a sequencial order based on memory address)
	UNIT_STATE_ATTACK2_DAMAGE_DICE          : 0x30,
	UNIT_STATE_ATTACK2_DAMAGE_SIDE          : 0x31,
	UNIT_STATE_ATTACK2_DAMAGE_BASE          : 0x32,
	UNIT_STATE_ATTACK2_DAMAGE_BONUS         : 0x33,
	UNIT_STATE_ATTACK2_DAMAGE_LOSS_FACTOR   : 0x34,
	UNIT_STATE_ATTACK2_WEAPON_SOUND         : 0x35,
	UNIT_STATE_ATTACK2_ATTACK_TYPE          : 0x36,
	UNIT_STATE_ATTACK2_MAX_TARGETS          : 0x37,
	UNIT_STATE_ATTACK2_INTERVAL             : 0x38,
	UNIT_STATE_ATTACK2_INITIAL_DELAY        : 0x39,
	UNIT_STATE_ATTACK2_RANGE                : 0x40,
	UNIT_STATE_ATTACK2_RANGE_BUFFER         : 0x41,
	UNIT_STATE_ATTACK2_DAMAGE_MIN           : 0x42,
	UNIT_STATE_ATTACK2_DAMAGE_MAX           : 0x43,
	UNIT_STATE_ATTACK2_BACK_SWING           : 0x44,
	UNIT_STATE_ATTACK2_TARGET_TYPES         : 0x45,
	UNIT_STATE_ATTACK2_SPILL_DIST           : 0x46,
	UNIT_STATE_ATTACK2_SPILL_RADIUS         : 0x47,
	UNIT_STATE_ATTACK2_WEAPON_TYPE          : 0x59,
	// general attributes
	UNIT_STATE_ARMOR_TYPE                   : 0x50,
	UNIT_STATE_RATE_OF_FIRE                 : 0x51, // global attack rate of unit, work on both attacks
	UNIT_STATE_ACQUISITION_RANGE            : 0x52, // how far the unit will automatically look for targets
	UNIT_STATE_LIFE_REGEN                   : 0x53,
	UNIT_STATE_MANA_REGEN                   : 0x54,
	UNIT_STATE_MAX_LIFE                     : 0x1,
	UNIT_STATE_MAX_MANA                     : 0x3,
	UNIT_STATE_MIN_RANGE                    : 0x55,
	UNIT_STATE_AS_TARGET_TYPE               : 0x60,
	UNIT_STATE_TYPE                         : 0x61,
	// ...starts from 0x62
}
	
class jassGlobalObj
{
	constructor(g) 
	{
		this.ObjAddr = g
		this.name = g.add(0x14).readPointer().readCString()
		//this._array = g.add(0x18).readU32()
		this._type = g.add(0x1c).readU32()
		this._value = g.add(0x20).readPointer()
		//console.log(this.name, this._type, this._value)
		this.value = this.readGlobalVariable(this._type, this._value)
	}
	readGlobalVariable(type_, value_)
	{
		switch(type_){
			case OPCODE_VARIABLE.INTEGER: return value_.toInt32();
			case OPCODE_VARIABLE.REAL: return hex2float(value_);
			case OPCODE_VARIABLE.STRING: return jass.getStringById(value_.toInt32());
			case OPCODE_VARIABLE.HANDLE: return value_;
			case OPCODE_VARIABLE.BOOLEAN: return value_>0;
			case OPCODE_VARIABLE.INTEGER_ARRAY: return value_==0?null:this.readGlobalVariable_INTEGER_ARRAY(value_);
			case OPCODE_VARIABLE.REAL_ARRAY: return value_==0?null:this.readGlobalVariable_REAL_ARRAY(value_);			
			case OPCODE_VARIABLE.STRING_ARRAY: return value_==0?null:this.readGlobalVariable_STRING_ARRAY(value_);
			case OPCODE_VARIABLE.HANDLE_ARRAY: return value_==0?null:this.readGlobalVariable_HANDLE_ARRAY(value_);
			case OPCODE_VARIABLE.BOOLEAN_ARRAY: return value_==0?null:this.readGlobalVariable_BOOLEAN_ARRAY(value_);
			default:
				console.error("Unimplemented:" + type_)
			break;
		}
	}
	readGlobalVariable_BOOLEAN_ARRAY(value_)
	{
		const result = []
		const size = value_.add(8).readU32()
		const arrayVal = value_.add(0xc).readPointer()
		for (let j = 0; j < size; j++) {
			result.push(arrayVal.add(j*4).readInt()>0)
		}
		return result;
	}
	readGlobalVariable_HANDLE_ARRAY(value_)
	{
		const result = []
		const size = value_.add(8).readU32()
		const arrayVal = value_.add(0xc).readPointer()
		for (let j = 0; j < size; j++) {
			result.push(arrayVal.add(j*4).readPointer())
		}
		return result;
	}
	readGlobalVariable_INTEGER_ARRAY(value_)
	{
		const result = []
		const size = value_.add(8).readU32()
		const arrayVal = value_.add(0xc).readPointer()
		for (let j = 0; j < size; j++) {
			result.push(arrayVal.add(j*4).readInt())
		}
		return result;
	}
	readGlobalVariable_REAL_ARRAY(value_)
	{
		const result = []
		const size = value_.add(8).readU32()
		const arrayVal = value_.add(0xc).readPointer()
		for (let j = 0; j < size; j++) {
			result.push(hex2float(arrayVal.add(j*4).readU32()))
		}
		return result;
	}
	readGlobalVariable_STRING_ARRAY(value_)
	{
		const result = []
		const size = value_.add(8).readU32()
		const arrayVal = value_.add(0xc).readPointer()
		for (let j = 0; j < size; j++) {
			result.push(jass.getStringById(arrayVal.add(j*4).readU32()))
		}
		return result;
	}
	setvalue(v, arrayIndex) 
	{
		const valueAddr = this.ObjAddr.add(0x20)
		//console.log("valueAddr:" + valueAddr)
		
		switch(this._type){
			case OPCODE_VARIABLE.INTEGER: valueAddr.writeInt(v); break;
			case OPCODE_VARIABLE.REAL: valueAddr.writeU32(float2Hex(v)); break;
			//case OPCODE_VARIABLE.STRING: jass.getStringById(value_.toInt32()); break;
			case OPCODE_VARIABLE.HANDLE: valueAddr.writeU32(v); break;
			case OPCODE_VARIABLE.BOOLEAN: valueAddr.writeU32((v)?1:0); break;
			//case OPCODE_VARIABLE.INTEGER_ARRAY: return readGlobalVariable_INTEGER_ARRAY(value_.readPointer());
			//case OPCODE_VARIABLE.REAL_ARRAY: return readGlobalVariable_REAL_ARRAY(value_.readPointer());
			//case OPCODE_VARIABLE.STRING_ARRAY: return readGlobalVariable_STRING_ARRAY(value_.readPointer());
			default:
				console.error("Unimplemented:" + this._type)
			break;
		}
	}
}


		
const jass = 
{
	commonCallBack:()=>{},
	initJassFunc()	
	{
		this._call_cache={}
		this._JassApiTable=[]
		//加载函数列表
		this._JassApiTable = this.loadJassApisFromMemory()
		//加入jassApi
		for(let iobj of this._JassApiTable) this[iobj.name] = (...arg)=> this.call(iobj.name, ...arg)
	},
	init()
	{
		if(this._inited) return 
		
		this.initJassFunc()
		
		this._callback_cahceIdx = 0
		this._callback_cahce = {}
		
		this._createTriggerCallMiddle()
		
		this._inited = true
	},
	_createTriggerCallMiddle() 
	{

		const mmoo = VirtualAlloc(NULL, 0x1000, 0x1000, 4)

		const xx = new X86Writer(mmoo)
		xx.putCallAddress(mmoo.add(0x10))
		xx.putMovRegU32('eax', 1)
		xx.putRetImm(0x14)
		xx.flush()

		const xx10 = new X86Writer(mmoo.add(0x10))
		xx10.putMovRegU32('eax', 1)
		xx10.putRet()
		xx10.flush()
		
		
		const xx3 = new X86Writer(mmoo.add(0x60)) 
		xx3.putPushU32(0)
		xx3.putPushax()
		
		xx3.putCmpRegI32('edx', 0x80000000);
		xx3.putJccShortLabel('ja', 'skipfunc', 'no-hint');
		//小于0x80000000调用原始函数
		xx3.putMovRegAddress("ecx", mmoo.add(0x100))
		xx3.putJmpShortLabel('end')
		
		xx3.putLabel('skipfunc');
		xx3.putMovRegAddress("ecx", mmoo)

		xx3.putLabel('end');
		xx3.putLeaRegRegOffset("eax","esp",32)
		xx3.putMovRegPtrReg("eax","ecx")
		
		xx3.putPopax()
		xx3.putRet()
		xx3.flush()

		//原始函数
		const xx2 = new X86Writer(mmoo.add(0x100))
		xx2.putPushReg("ebp")
		xx2.putMovRegReg("ebp","esp")
		xx2.putPushReg("esi")
		xx2.putPushReg("edi")
		//Game.dll+7E2FA5 - 8B F2                 - mov esi,edx
		xx2.putJmpAddress(GameDll.add(0x7E2FA5))
		xx2.flush()

		Memory.protect(mmoo,0x1000, 'rwx')
		// Game.dll+7E2FA0
		Memory.patchCode(GameDll.add(0x7E2FA0), 5, code => {
		  const cw = new X86Writer(code);
		  cw.putJmpAddress(mmoo.add(0x60));
		  cw.flush()
		});
		const that = this
		
		Interceptor.replace(mmoo, new NativeCallback((p1,p2,p3,p4,p5,p6,p7) => {
			//console.log("p1:"+p1+",p2:"+p2+",p3:"+p3+",p4:"+p4+",p5:"+p5+",p6:"+p6+",p7:"+p7)
			const triggerActionId = p2
			if(triggerActionId >= 0x8F000000) 
			{
				that.commonCallBack(triggerActionId.add(-0x8F000000))
			}
			else if(triggerActionId >= 0x80000000) 
			{
				that._callback(triggerActionId)
			}
			return 1
		}, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'], "fastcall"));
		
		Interceptor.replace(mmoo.add(0x10), new NativeCallback((p1,p2) => {
			//console.log("p1:"+p1+",p2:"+p2)
			const triggerActionId = p2
			if(triggerActionId >= 0x8F000000) 
			{
				that.commonCallBack(triggerActionId.add(-0x8F000000))
			}
			else if(triggerActionId >= 0x80000000) 
			{
				that._callback(triggerActionId)
			}
			return 1
		}, 'int', ['pointer', 'pointer'], "fastcall"));
		
	},
	_callback(actionId)
	{
		const fn = this._callback_cahce[actionId]
		if(fn)
		{
			fn()
		}else{
			console.log("actionId:" + actionId+" action not found")
		}
	},
	GetInstanceCall_5()
	{
		if(this._i5_cache)
		{
			return this._i5_cache
		}
		const pattern = '00 50 72 6F 70 2E 63 70 70 00'
		for(let a of Process.enumerateRanges("rw"))
		{
			if(a.size==4096)
			{
				try
				{
					const results = Memory.scanSync(a.base, a.size, pattern);				
					if (results && results.length > 0) 
					{
						if((results[0].address &0xff) ==0x6b)
						{
							//94
							return this._i5_cache = results[0].address.add(0x29).readPointer()
						}
					}
				}catch(e){}
			}
		}		
		return null
	},
	jass_vm_t(idx=1)
	{
		const i5 = this.GetInstanceCall_5()
		if(i5)
		{
			return i5.add(0x90).readPointer().add(4*idx).readPointer();
		}else{
			console.log("*[warning]static jass_vm_t used...")
			return Module.findBaseAddress('War3Plugin.dll').add(0x193FA4).readPointer();
		}
	},
	from_string(p)
	{
		return p.add(8).readPointer().add(0x1c).readPointer().readCString()
	},
	getStringById(Id, vmIdx=1)
	{
		const _string_table = this.jass_vm_t(vmIdx).add(0x2874).readPointer()
		const strCnt = _string_table.add(0x4).readInt()
		if(Id >= strCnt) return null
		let stringitem = _string_table.add(0x8).readPointer().add(Id*0x10)
		var aa = stringitem.add(8).readPointer()
		if(!aa) return null
		return aa.add(0x1c).readPointer().readCString()
	},
	JassCallTypeConvert(par_)
	{
		if(par_=="V")return "void"
		else if(par_=="I")return "int"
		else if(par_=="B")return "bool"
		else if(par_=="R")return "pointer"
		else if(par_=="S")return "pointer"
		else if(par_=="C")return "pointer"
		else if(par_[0]=="H")return "pointer"
		else
		{
			console.error("不知如何处理类型："+par_)
			return "pointer"
		}
	},
	loadJassApisFromMemory() 
	{
		const instance5 = this.GetInstanceCall_5()
		
		let itembase = instance5.add(0x18 + 0xc).readPointer()
	/* 
	+c prev
	+14 next
	+18 fnname
	+1c fn_addr
	+24 fn_param 
	*/		
		const allfuncs = []
		for (let i = 0; i < 2000; i++) {
			const name = itembase.add(0x18).readPointer().readCString()
			const addr = itembase.add(0x1c).readPointer()
			const param_num = itembase.add(0x20).readPointer()
			const param = itembase.add(0x24).readPointer().readCString()
			 
			const module = Process.findModuleByAddress(addr)
			const offset = module?addr.add(-module.base):0
			//console.log(i + ",addr:" + addr + ",name:" + name + "\t" + param+"\t"+offset)
			allfuncs.push({
				name:name,
				dll:module?module.name:"UNKNOWN",
				offset:offset,
				param:param,
				param_num:param_num,
				addr:addr
			})
			const hasn = itembase.add(0x14).readU32() 
			if (hasn > 0x80000000) break;
			itembase = ptr(hasn)
		}
		return allfuncs
	},
	getFunc(name)
	{
		const f1 = this._JassApiTable.filter(x=>(x.name==name) || (x.dll.replace(".dll",'')+"."+x.name)==name)
		if(f1.length == 0)
		{
			console.error("JassApi not found : " + name)
			return
		}
		return f1[0]
	},
	call(name, ...p1)
	{
		this.init()
		let callerObj = this._call_cache[name]
		if(!callerObj)
		{
			const f1 = this._JassApiTable.filter(x=>(x.name==name) || (x.dll.replace(".dll",'')+"."+x.name)==name)
			if(f1.length == 0)
			{
				console.error("JassApi not found : " + name)
				return
			}
			if(f1.length > 1)
			{
				console.error("JassApi multiple implement found : " + name +"\r\n"+JSON.stringify(f1))
				return
			}
			const funcdefine = f1[0]
			const par_in = []
			let par_out = ""
			let isH = false;
			let Hname = "";
			for(let a of funcdefine.param)
			{
				if(a=="(") continue;
				if(a==")") {
					par_out = funcdefine.param.substr(funcdefine.param.indexOf(")")+1)
					break;
				}
				
				if(a==";")
				{
					isH = false
					Hname = Hname + a
					par_in.push(Hname)
				}
				else if(isH)
				{
					Hname = Hname + a
				}
				else if(a=="H")
				{
					isH = true
					Hname = "H"		
				}else{
					par_in.push(a)
				}
			}
			var par_out_2 = this.JassCallTypeConvert(par_out)
			const par_in_2 = [...par_in]
			for(let ii=0;ii<par_in_2.length;ii++)
			{
				par_in_2[ii] = this.JassCallTypeConvert(par_in_2[ii])
			}
			//console.log("in => " + JSON.stringify(par_in_2))
			//console.log("out => " + par_out)
			const caller = new NativeFunction(funcdefine.addr, par_out_2, par_in_2, 'stdcall');
			callerObj = {
				params:par_in,
				retule:par_out,
				invoke:caller
			}
			this._call_cache[name] = callerObj
		}
		
		//console.log(JSON.stringify(callerObj.params))
		const v_in = []
		for(let idx=0;idx<callerObj.params.length;idx++)
		{			
			const iobj = callerObj.params[idx]
			if(idx>=p1.length)
			{
				console.error("参数不够："+JSON.stringify(callerObj.params))
				return
			}
			let ival = p1[idx]
			if(iobj=='R')
			{
				ival = createfloat(ival)
			}
			else if(iobj=='C')
			{
				if(typeof ival== 'function')
				{
					//修改js后函数无法还原
					const actionId = ptr(0x80000000).add(++this._callback_cahceIdx)
					this._callback_cahce[actionId.toString()] = ival
					ival = actionId
				}else if(typeof ival== 'number'){
					const actionId = ptr(0x8F000000).add(parseInt(ival))
					ival = actionId
				}else{
					console.error("第【"+idx+"】个参数必须是一个函数")
					return
				}
			}
			else if(iobj=='S')
			{
				ival = createString(ival)
			}
			else if(iobj=='B')
			{
				if(typeof ival != "boolean") 
				{
					console.error("第【"+idx+"】个参数必须是boolean")
					return
				}
				ival = ival?1:0
			}
			if(ival===null)ival = ptr(0)
			v_in.push(ival)
			
		}
		//console.log(JSON.stringify(v_in))
		const r = callerObj.invoke(...v_in)
		if(callerObj.retule=='R')
		{
			return hex2float(r)
		}
		else if(callerObj.retule=='S')
		{
			return this.getStringById(r)
		}
		return r
	},
	getAllStringCount(vmIdx = 1)
	{
		const string_table = this.jass_vm_t(vmIdx).add(0x2874).readPointer()
		const strCnt = string_table.add(0x4).readU32()
		return strCnt
	},
	getAllString(vmIdx = 1)
	{
		const string_table = this.jass_vm_t(vmIdx).add(0x2874).readPointer()
		const strCnt = string_table.add(0x4).readU32()
		let itembase = string_table.add(0x8).readPointer()
		const strings__ = {}
		for (let i = 0; i < strCnt; i++) {
			const stringitem = itembase.add(i*0x10)
			var aa = stringitem.add(8).readPointer()
			if(!aa)
			{
				strings__[i] = null
			}else{
				const v = aa.add(0x1c).readPointer().readCString()
				strings__[i] = v
			}
		}
		return strings__
	},
	dumpGlobalVariable(vmIdx = 1) {
		const global_table = this.jass_vm_t(vmIdx).add(0x285C).readPointer()
		let itembase = global_table.add(0xC).readPointer()
		for (let i = 0; i < 10000; i++) {
			const name = itembase.add(0x14).readPointer().readCString()
			const array_ = itembase.add(0x18).readU32()
			const type_ = itembase.add(0x1c).readU32()
			const value_ = itembase.add(0x20).readPointer()
			
			//if(type_==8)
			{
				console.log(itembase+":"+name +"\t"+array_+"\t" +"\t"+type_ +"\t"+value_ +"\t")
			}
			
			const hasn = itembase.add(0x10).readU32()
			if (hasn > 0x80000000) break;
			itembase = ptr(hasn)
		}
	},
	getGlobalVariable(name, vmIdx = 1) {
		const global_table = this.jass_vm_t(vmIdx).add(0x285C).readPointer()
		let itembase = global_table.add(0xC).readPointer()

		for (let i = 0; i < 10000; i++) {
			const name2 = itembase.add(0x14).readPointer().readCString()
			if(name2==name)
			{
				return new jassGlobalObj(itembase)
			}
			const hasn = itembase.add(0x10).readU32()
			if (hasn > 0x80000000) break;
			itembase = ptr(hasn)
		}
	},
	getAllItems()
	{
		const item_table = GameDll.add(0xBE6114)
		const mask = item_table.add(0x24).readPointer()
		const itembase = item_table.add(0x1C).readPointer().add(8)
		//console.log(mask, itembase)
		const allitems = []
		for(let im=0;im<mask;im++)
		{
			let slot = itembase.add(0xC * im).readPointer()
			for(let i=0;i<10;i++)
			{
				if(slot>0x7fffffff || slot<0x10000)
				{
					break
				}
				//const hash = slot.add(0x4)
				const aitemobj = {
					addr: slot,
					id : slot.add(0x1c).readCString(4),
					type : slot.add(0xA8).readU32(),
					name : ""
				}
				if(slot.add(0x2c).readPointer()!=0)
				{
					aitemobj.name = slot.add(0x2c).readPointer().readPointer().readUtf8String()
				}
				if(slot.add(0x26c).readPointer()!=0)
				{
					aitemobj.usertip = slot.add(0x26c).readPointer().readPointer().readUtf8String()
				}
				if(slot.add(0x260).readPointer()!=0)
				{
					aitemobj.tip = slot.add(0x260).readPointer().readPointer().readUtf8String()
				}
				//模型文件
				/*
				if(slot.add(0x24c).readPointer()!=0)
				{
					aitemobj.art = slot.add(0x24c).readPointer().readPointer().readUtf8String()
				}
				*/
				if(aitemobj.name)
					allitems.push(aitemobj)
				slot = slot.add(0xc).readPointer()
			}
		}
		//console.log(JSON.stringify(allitems))
		return allitems
	}
	
}
jass.init()

const jasslua = 
{
	jasshooked : {},
	onluaload:(name, script)=>{},
	
	_getJassHandleFromJassDll()
	{
		const dll = Module.findBaseAddress('jass.dll')
		const k1 = dll.add(0x28B644).readPointer()
		const k2 = dll.add(0x28C92C).readPointer()
		const k3 = dll.add(0x28E250).readPointer()
		if(k1.toString()!=k2.toString() || k1.toString()!=k3.toString())
		{
			console.warn("*[jass.dll] lua handle probably incorrect!!!",k1,k2,k3)
		}
		return k1
	},
	hook(luadll) {
		let jasshooked = this.jasshooked
		if (jasshooked[luadll]) return;
		const that = this
		let jass_lua_load = Module.findExportByName(luadll, "lua_load")
		if (jass_lua_load) {
			console.log("============ " + luadll + " ok =================")
			
			Interceptor.attach(jass_lua_load, {
				onEnter: function (args) {
					if (!jasshooked[luadll]?.handle) {
						jasshooked[luadll].handle = args[0]
						console.log("L[" + luadll + "] is ok:=====>" + jasshooked[luadll].handle);
					}
					
					//console.log('lua_load '+args[0]+", "+args[1]+", "+args[2].readU32().toString(16)+", "+args[3].readU32().toString(16)+", "+args[4]+", "+args[5]);
					//console.log('Context  : ' + JSON.stringify(this.context));
					//console.log('load_lua_from  : ' + this.context.esp.readPointer());

					var data = ptr(args[2].readU32())
					var len = args[2].add(4).readU32()
					var luadata = ""
					var chunkname = ""
					try {
						luadata = data.readUtf8String()
					} catch {
					}
					try {
						chunkname = args[3].readUtf8String()
					} catch {
						chunkname = new Date().getTime().toString()
					}
					if (luadata.startsWith(chunkname)) 
					{
						//没有名字的，chunkname会默认脚本前半部分
						chunkname = new Date().getTime().toString()
					}
					//console.log(chunkname, luadata)
					
					that.onluaload(chunkname, luadata)
					if (!luadata.startsWith("return ((require'jass.slk')")) {
						//这里dump所有执行的lua
						console.log(luadata)
						//send(chunkname, data.readByteArray(len))
					}
				},
				onLeave: function (retval) {
				}
			});

			let luaL_loadstring = Module.findExportByName(luadll, "luaL_loadstring")
			let luaL_loadbufferx = Module.findExportByName(luadll, "luaL_loadbufferx")
			let lua_settop = Module.findExportByName(luadll, "lua_settop")
			let lua_pcall = Module.findExportByName(luadll, "lua_pcallk")
			let lua_tostring = Module.findExportByName(luadll, "lua_tolstring")

			let luaL_loadstringCall = new NativeFunction(luaL_loadstring, 'pointer', ['pointer', 'pointer'], 'stdcall');
			let lua_pcallCall = new NativeFunction(lua_pcall, 'int', ['pointer', 'int32', 'int32', 'int32', 'int32', 'int32'], 'stdcall');
			let lua_tolstringCall = new NativeFunction(lua_tostring, 'pointer', ['pointer', 'int32', 'int32'], 'stdcall');
			let luaL_loadbufferxCall = new NativeFunction(luaL_loadbufferx, 'int', ['pointer', 'pointer', 'int32', 'pointer', 'int32'], 'stdcall');
			let lua_settopCall = new NativeFunction(lua_settop, 'void', ['pointer', 'int32'], 'stdcall');
			
			/*
			Interceptor.attach(lua_settop, {
				onEnter: function (args) {
					if (!jasshooked[luadll]?.handle) {
						jasshooked[luadll].handle = args[0]
						console.log("L[" + luadll + "] is ok:=====>" + jasshooked[luadll].handle);
					}
				},
				onLeave: function (retval) {
				}
			});
			*/
			
			jasshooked[luadll] = {
				handle: 0,
				address: {
					luaL_loadstring,
					luaL_loadbufferx,
					lua_settop,
					lua_pcall,
					lua_tostring,
					lua_load: jass_lua_load
				},
				call: {
					luaL_loadstringCall,
					lua_pcallCall,
					lua_tolstringCall,
					luaL_loadbufferxCall,
					lua_settopCall,
				}
			}
			if(luadll=='jass.dll')
			{				
				jasshooked["jass.dll"].handle = this._getJassHandleFromJassDll()
			}
		}
	},
	exe(ssx) {
		let ss = "";
		if (typeof ssx == 'function') {
			ss = ssx()
		} else {
			ss = ssx
		}
		const jasshooked = this.jasshooked
		let L = null
		if(jasshooked["luacore.dll"] && jasshooked["luacore.dll"].handle)
		{
			L = jasshooked["luacore.dll"]
		}
		else if(jasshooked["jass.dll"])
		{
			if(jasshooked["jass.dll"].handle==0)
			{
				jasshooked["jass.dll"].handle = this._getJassHandleFromJassDll()
			}
			L = jasshooked["jass.dll"]
		}
		//	强制手动设置
		if (this._engine == 1) {
			L = jasshooked["luacore.dll"]
		} else if (this._engine == 2) {
			L = jasshooked["jass.dll"]
		}
		if (L) {
			//console.log(JSON.stringify(L))
			if (L.handle == 0) {
				console.log("L.handle 初始化未完成")
				return
			}

			if (typeof L.handle == "string") L.handle = ptr(L.handle)

			let funss = "local function code2hex(code) return (string.byte(code,1) <<24) + (string.byte(code,2) <<16)+(string.byte(code,3) <<8)+string.byte(code,4) end; \r\n"
				+ " local jcom= require 'jass.common';local jg= require'jass.globals';local japi = require 'jass.japi';local dbg = require 'jass.debug';\r\n"//local bli = require 'Blizzard';
				+ ss;
			try {
				let scriptlen = funss.length;
				let zw = funss.match(/[^\x00-\xff]/ig);
				if (zw) scriptlen += (zw.length * 2)

				let script = Memory.alloc(scriptlen + 0x100)
				script.writeUtf8String(funss)
				//dumpAddr(script,0x100)

				L.call.lua_settopCall(L.handle, 0);
				let rr = L.call.luaL_loadbufferxCall(L.handle, script, scriptlen, script, 0)
				if (rr != 0) {
					let ess = L.call.lua_tolstringCall(L.handle, 1, 0)
					console.log("Err:" + ess.readCString())
				}
				let rescode = L.call.lua_pcallCall(L.handle, 0, -1, 0, 0, 0)
				if (rescode != 0) {
					let ess = L.call.lua_tolstringCall(L.handle, 1, 0)
					console.log("Err2:" + ess.readCString())
				}
			} catch (e) {
				console.log("ERRRRRRRRRRRRRRRRRRRRRRRRRRR=====>" + e.message);
				console.log("ERRRRRRRRRRRRRRRRRRRRRRRRRRR=====>" + e);
				console.log("ERRRRRRRRRRRRRRRRRRRRRRRRRRR=====>" + JSON.stringify(e));
			}
		} else {
			console.error("lua 未初始化。")
		}
	}

}

var jass_dll = Module.findBaseAddress('jass.dll')
if(jass_dll)
{
	jasslua.hook("jass.dll")	
}else{
	var wapi_LoadLibraryA = Module.findExportByName('kernel32.dll', "LoadLibraryA");
	Interceptor.attach(wapi_LoadLibraryA, {
		onEnter: function (args) {
			this.dllpath = args[0].readUtf8String();
		},
		onLeave: function (retval) {
			if (this.dllpath.indexOf("jass.dll") > -1) {
				console.log("wapi_LoadLibrary end......" + this.dllpath)
				jasslua.hook("jass.dll");
			}
		}
	});
}
jasslua.hook("luacore.dll")


const GameUI = {
	mouseX:0,
	mouseY:0,
	onKeyPress(key){
		//非常规键值
		console.log("pressKey:"+key)
	},
	init()
	{
		const that = this
		that.GetAsyncKeyState = new NativeFunction(Module.findExportByName(null,"GetAsyncKeyState"), 'int', ['int']),
		that.IsControlKeyPressed = new NativeFunction(GameDll.add(0x576f0), 'pointer', ['int'],'thiscall')
		
		Interceptor.attach(GameDll.add(0x364c40), {
			onEnter: function (args) {
				that.mouseX = args[2].readU32()
				that.mouseY = args[2].add(4).readU32()
			}
		})
		Interceptor.attach(GameDll.add(0x3520F0), {
			onEnter: function (args) {
				const key = args[0].add(0x10).readU32()
				const t2 = jass.CreateTimer()
				jass.TimerStart(t2, 0, false, ()=>{
					that.onKeyPress(key)
					
					jass.DestroyTimer(t2)
				})
			}
		})
	},
	getMouseX(){
		return hex2float(this.mouseX)
	},
	getMouseY(){
		return hex2float(this.mouseY)
	},
	isShift(){
		return this.GetAsyncKeyState(16)!=0
	},
	isCtrl(){
		return this.GetAsyncKeyState(17)!=0
	},
	isAlt(){
		return this.GetAsyncKeyState(18)!=0
	},	
	IS_CHATTING(){
		return GameDll.add(0xbdaa14).readU32()==1
	}
}
GameUI.init()

/////////////////////////////////////////////////////////////////////
//////////////////////////////扩展///////////////////////////////////
/////////////////////////////////////////////////////////////////////


Interceptor.attach(GameDll.add(0x399630), {
	onEnter: function (args) {
	},
	onLeave: function (retval) {
		var ss = retval.readUtf8String()
		//输入不了中文（函数中替换掉
		if(ss == '?'){
			msghandle()
		}
		if(ss == '000'){
			retval.writeUtf8String("吃饭睡觉打豆豆")
		}else if(ss == '001'){
			retval.writeUtf8String("天天RPG")
		}else if(ss == 'mm'){
			retval.writeUtf8String("墨眉")
		}
	}
}) 

function getSelectUnit()
{
	let player = jass.GetTriggerPlayer()
	if(player==0)player = jass.Player(0)
	
	const g = jass.CreateGroup()
	jass.GroupEnumUnitsSelected(g, player, null);
	const unit1 = jass.FirstOfGroup(g)
	jass.DestroyGroup(g)
	return unit1
}
jass.commonCallBack = (x)=>
{
	//console.log("call commonCallBack:" + x)
	
	if(x == 2)
	{
		const player = jass.call('GetTriggerPlayer')
		const msgpp = jass.GetEventPlayerChatString().split(" ")
		const msg = msgpp[0]
		//jass.call('DisplayTimedTextToPlayer',player,0,0,7,'|cffffcc00【金色】|r - |cffff0000【红色】|r - |cff339966【墨绿】|r - |cff00ccff【蓝色】|r - |cffc0c0c0【灰色】|r - |cffff00ff【紫色】|r - |Cff0af30a【绿】|r'+"-->"+msg)
		if(msg == ".")
		{
			//传送选中角色到鼠标位置
			jass.SetUnitPositionLoc(getSelectUnit(),jass.Location(GameUI.getMouseX(), GameUI.getMouseY()))
		}
		else if(msg == "1")
		{
			//杀死选中对象
			jass.KillUnit(getSelectUnit())
		}
		else if(msg == "11")
		{
			//杀死选中对象
			const target = getSelectUnit()
			
			const playerUnits = jass.CreateGroup()
			jass.GroupEnumUnitsOfPlayer(playerUnits, jass.GetTriggerPlayer(), null)
			const actor = jass.FirstOfGroup(playerUnits)
			jass.DestroyGroup(playerUnits)
			console.log("UnitName:" + jass.GetUnitName(actor))
			
			//获取目标最大HP
			const UNIT_STATE_MAX_LIFE = jass.getGlobalVariable("UNIT_STATE_MAX_LIFE").value
			const maxhp = jass.GetUnitState(target, UNIT_STATE_MAX_LIFE)
			
			const ATTACK_TYPE_CHAOS = jass.getGlobalVariable("ATTACK_TYPE_CHAOS").value
			const DAMAGE_TYPE_ENHANCED = jass.getGlobalVariable("DAMAGE_TYPE_ENHANCED").value
			
			jass.UnitDamageTarget(actor, target, maxhp, true, true, ATTACK_TYPE_CHAOS, DAMAGE_TYPE_ENHANCED, null)
		}
		else if(msg == "12")
		{
			//杀死鼠标指针1000范围内的敌人
			const playerUnits = jass.CreateGroup()
			jass.GroupEnumUnitsOfPlayer(playerUnits, jass.GetTriggerPlayer(), null)
			const actor = jass.FirstOfGroup(playerUnits)
			console.log("UnitName:" + jass.GetUnitName(actor))
			jass.DestroyGroup(playerUnits)
			
			const UNIT_STATE_MAX_LIFE = jass.getGlobalVariable("UNIT_STATE_MAX_LIFE").value
			const ATTACK_TYPE_CHAOS = jass.getGlobalVariable("ATTACK_TYPE_CHAOS").value
			const DAMAGE_TYPE_ENHANCED = jass.getGlobalVariable("DAMAGE_TYPE_ENHANCED").value
			
			const targetGroup = jass.CreateGroup()
			jass.GroupEnumUnitsInRange(targetGroup, GameUI.getMouseX(), GameUI.getMouseY(), 1000, null)
			jass.ForGroup(targetGroup, ()=>{
				const curUnit = jass.GetEnumUnit()
				if(jass.IsUnitEnemy(curUnit,player))
				{
					//console.log(" kill >> :" + jass.GetUnitName(curUnit))
					const maxhp = jass.GetUnitState(curUnit, UNIT_STATE_MAX_LIFE)
					jass.UnitDamageTarget(actor, curUnit, maxhp, true, true, ATTACK_TYPE_CHAOS, DAMAGE_TYPE_ENHANCED, null)
				}
			})
			jass.DestroyGroup(targetGroup)
			
		}
		else if(msg == "wd")
		{
			//选中对象无敌
			jass.SetUnitInvulnerable(getSelectUnit(),true); 
		}
		else if(msg == "wd-")
		{
			//选中对象取消无敌
			jass.SetUnitInvulnerable(getSelectUnit(),false);
		}
		else if(msg == "aa1")
		{
			Trigger_aa1 = jass.CreateTrigger()
			jass.TriggerRegisterTimerEvent(Trigger_aa1, 1, true)
			jass.TriggerAddAction(Trigger_aa1, 3)  
		}
		else if(msg == "aa2")
		{
			jass.DestroyTrigger(Trigger_aa1)
		}
		else if(msg == "give"){
			if(msgpp.length<2){
				jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffff0000指令错误 【give id】 |r')
			}else{
				const cnt = msgpp[2]||1
				for(let i=0;i<cnt;i++)
				{
					jass.UnitAddItemById(getSelectUnit(),code2hex(msgpp[1]));
				}
			}
		}
	}
	else if(x == 3)
	{
		Trigger_aa1 = jass.GetTriggeringTrigger()
		//杀死选中对象1000范围内的怪
		const player = jass.Player(0)
		
		const playerUnits = jass.CreateGroup()
		jass.GroupEnumUnitsOfPlayer(playerUnits, player, null)
		let actor = jass.FirstOfGroup(playerUnits)
		//console.log("UnitName:" + jass.GetUnitName(actor))
		jass.DestroyGroup(playerUnits)
		
		const UNIT_STATE_MAX_LIFE = jass.getGlobalVariable("UNIT_STATE_MAX_LIFE").value
		const ATTACK_TYPE_CHAOS = jass.getGlobalVariable("ATTACK_TYPE_SIEGE").value
		const DAMAGE_TYPE_ENHANCED = jass.getGlobalVariable("DAMAGE_TYPE_UNKNOWN").value
		
		const targetGroup = jass.CreateGroup()
		jass.GroupEnumUnitsInRange(targetGroup, jass.GetUnitX(actor), jass.GetUnitY(actor), 2000, null)
		jass.ForGroup(targetGroup, ()=>{
			const curUnit = jass.GetEnumUnit()
			if(jass.IsUnitEnemy(curUnit,player))
			{
				let  maxhp = jass.GetUnitState(curUnit, UNIT_STATE_MAX_LIFE)
				const hp = jass.GetUnitState(curUnit, jass.getGlobalVariable("UNIT_STATE_LIFE").value)
				//console.log(" kill >> :" + jass.GetUnitName(curUnit)+", HP:"+hp+"/"+maxhp)

				jass.UnitDamageTarget(actor, curUnit, maxhp, true, true, ATTACK_TYPE_CHAOS, DAMAGE_TYPE_ENHANCED, null)
			}
		})
		jass.DestroyGroup(targetGroup)
		
	}
}
var spawntype=1;
var spawnId;
var spawnOwn;
var Trigger_aa1;

GameUI.onKeyPress=(key)=>{
	//console.log("aaaaaaaaa>"+key,GameUI.isCtrl(),GameUI.isShift(),GameUI.isAlt())
	if(key == 67)
	{
		// press C
		if(GameUI.isCtrl())
		{
			//ctrl
			const unit1 = getSelectUnit()
			if(unit1.toInt32()!=0)
			{
				spawnOwn = jass.GetOwningPlayer(unit1)
				spawnId = jass.GetUnitTypeId(unit1)
				spawntype = 1
				const name = jass.GetUnitName(unit1)
				jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|C0000ff00 unit copied, '+spawnOwn+', '+hex2code(spawnId)+','+name+'|r')
				return;
			}
			//选择光标位置的物品
			jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffff0000 '+GameUI.getMouseX()+","+GameUI.getMouseY()+'|r')
			let itemname;
			const mx = GameUI.getMouseX()
			const my = GameUI.getMouseY()
			jass.EnumItemsInRect(jass.GetWorldBounds(), null,()=>{
				const item = jass.GetEnumItem()
			
				const x = jass.GetItemX(item)
				const y = jass.GetItemY(item)
				if(Math.abs(mx-x)<50 && Math.abs(my-y)<50)
				{
					spawnId = jass.GetItemTypeId(item)
					itemname = jass.GetItemName(item)
				}
				
			})
			
			if(itemname){
				spawntype = 2			
				jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'item copied, '+hex2code(spawnId)+','+itemname)
			}
			else{
				jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffff0000 必须选择一个单位。 |r')
			}
		}
	}
	else if(key == 86)
	{
		// press V
		if(GameUI.isCtrl())
		{
			//ctrl
			if(spawntype==1)
			{
				if(spawnId && spawnOwn)
				{
					jass.CreateUnit(spawnOwn,spawnId, GameUI.getMouseX(), GameUI.getMouseY(),0)
				}else{
					jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffff0000 先使用Ctrl+C复制单位。 |r')
				}
			}else if(spawntype==2){
				if(spawnId)
				{
					jass.CreateItem(spawnId, GameUI.getMouseX(), GameUI.getMouseY());
				} 
			}else{
				
			}
		}
	}
	
}
function resetDamageFunc()
{
	var oldDmg = GameDll.add(0x67DC40)
	var funTable = GameDll.add(0xA4A824)
	Memory.protect(funTable, 4, 'rwx');
	funTable.writePointer(oldDmg)
	Memory.protect(funTable, 4, 'r-x');
}

function getFlag(offset)
{
	return GameDll.add(0x50).add(offset||0).readU8()
}
function setFlag(offset, v)
{	
	var p = GameDll.add(0x50).add(offset||0)
	Memory.protect(p, 4, 'rwx');
	p.writeU8(v)
	Memory.protect(p, 4, 'r-x');
}

function showcheatMsg()
{	
	const t2 = jass.CreateTimer()
	jass.TimerStart(t2, 0, false, ()=>{
		//jass.call('DisplayTimedTextToPlayer',jass.Player(0),0,0,7,'|cffffcc00【金色】|r - |cffff0000【红色】|r - |cff339966【绿色】|r - |cff00ccff【蓝色】|r - |cffc0c0c0【灰色】|r - |cffff00ff【紫色】|r'+"-->")
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|Cff0af30a作弊器初始化完成|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|Cff0af30a指令：|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc00?|r      |Cff0af30a显示此消息|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc00.|r      |Cff0af30a将选中对象移动到鼠标光标位置。|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc0011|r    |Cff0af30a杀死选中对象。|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc0012|r    |Cff0af30a杀死鼠标位置1000范围内的敌人。|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc00aa1|r  |Cff0af30a持续秒杀2000范围内的敌人。|r       |cffffcc00aa2|r  |Cff0af30a停止秒杀。|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc00wd|r  |Cff0af30a选中对象无敌。|r       |cffffcc00wd-|r  |Cff0af30a取消无敌。|r')
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc00give id|r  |Cff0af30a给予物品。|r')
		
		jass.DisplayTimedTextToPlayer(jass.Player(0),0,0,7,'|cffffcc00[Ctrl+C]|r  |Cff0af30a复制选中的单位。|r   |cffffcc00[Ctrl+V]|r  |Cff0af30a召唤复制的单位。|r')
		
	})
}

function msghandle() {
	if(getFlag(0)==1)
	{
		showcheatMsg()
		return;
	}
	setFlag(0,1)
	//resetDamageFunc()
	
	const t1 = jass.CreateTrigger()
	jass.TriggerRegisterPlayerChatEvent(t1, jass.Player(0), '', false)
	jass.TriggerRegisterPlayerChatEvent(t1, jass.Player(1), '', false)
	jass.TriggerRegisterPlayerChatEvent(t1, jass.Player(2), '', false)
	jass.TriggerRegisterPlayerChatEvent(t1, jass.Player(3), '', false)
	jass.TriggerAddAction(t1, 2)
	
	showcheatMsg()
	console.log("cheat commands loaded.")
}


Interceptor.attach(Module.findBaseAddress('Game.dll').add(0x7E2F60), {
	onEnter: function (args) {
		const jname = this.context.edx.readCString()
		console.log("call——, p0:"+jname)
		console.log(Module.findBaseAddress('Game.dll').add(0xBEF99C).readByteArray(0x40))
		console.log(Module.findBaseAddress('Game.dll').add(0xBEF99C).readPointer().readByteArray(0x40))
		if(jname=="main")
		{
			msghandle()
		}
	}
})

