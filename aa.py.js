//https://frida.re/docs/javascript-api
//https://github.com/actboy168/YDWE/blob/39b18198c784b589a944cb61220340541dcbf8bb/OpenSource/stormdll.txt
//http://jass.sourceforge.net/doc/api/common_j-functions.shtml
//http://jass.sourceforge.net/doc/api/Blizzard_j-source.shtml#2613
//https://github.com/actboy168/YDWE/blob/39b18198c784b589a944cb61220340541dcbf8bb/Development/Core/ydwar3/warcraft3/hashtable.h

/*
frida -p (ps War3).id -l aa.py.js


		
*/

function xzUnit() {
	//japi.DzGetSelectedLeaderUnit()
	return "local g = jcom.CreateGroup();\r\n" +
		//"jcom.GroupEnumUnitsOfPlayer(g, jcom.Player(0), null);"+
		"jcom.SyncSelections();jcom.GroupEnumUnitsSelected(g, jcom.Player(0), null);" +
		"local unit1 =jcom.FirstOfGroup(g); \r\n";

}

var commonJb = {
	"wd": "jcom.SetUnitInvulnerable(japi.DzGetSelectedLeaderUnit(),true); \r\n",
	"wd-": "jcom.SetUnitInvulnerable(japi.DzGetSelectedLeaderUnit(),false); \r\n",
	"1": "jcom.KillUnit(japi.DzGetSelectedLeaderUnit());",
	".": "jcom.SetUnitPositionLoc(japi.DzGetSelectedLeaderUnit(),jcom.Location(japi.DzGetMouseTerrainX(), japi.DzGetMouseTerrainY()))",
}

const VirtualAlloc = new NativeFunction(Module.findExportByName(null,"VirtualAlloc"), 'pointer', ['pointer', 'size_t', 'uint32', 'uint32']);

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
	var mmoo = Memory.alloc(0x200 + ss.length)
	mmoo.add(8).writePointer(mmoo.add(0x10))
	mmoo.add(0xc).writeU32(1)
	mmoo.add(0x10 + 0x1c).writePointer(mmoo.add(0x100))
	mmoo.add(0x100).writeUtf8String(ss)
	return mmoo
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
		//let ffile = new File("D:\\Game\\__MQ\\kk_funs.txt","r")
		//this._JassApiTable = JSON.parse(ffile.readText())
		//ffile.close()
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
		const newTrigger = new NativeCallback((p1,p2,p3,p4,p5,p6,p7) => {
			console.log("p1:"+p1+",p2:"+p2+",p3:"+p3+",p4:"+p4+",p5:"+p5+",p6:"+p6+",p7:"+p7)
			//const triggerActionId = p2
			//if(triggerActionId >= 0x8F000000) 
			//{
			//	that.commonCallBack(triggerActionId.add(-0x8F000000))
			//}
			//else if(triggerActionId >= 0x80000000) 
			//{
			//	console.log("aaaaaaaaaaaa????????????????????")
			//	that._callback(triggerActionId)
			//}
			return 1
		}, 'int', ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer'], "fastcall")
		
		const newTrigger2 = new NativeCallback((p1,p2) => {
			console.log("p1:"+p1+",p2:"+p2)
			//const triggerActionId = p2
			//if(triggerActionId >= 0x8F000000) 
			//{
			//	that.commonCallBack(triggerActionId.add(-0x8F000000))
			//}
			//else if(triggerActionId >= 0x80000000) 
			//{
			//	console.log("aaaaaaaaaaaa????????????????????")
			//	that._callback(triggerActionId)
			//}
			return 1
		}, 'int', ['pointer', 'pointer'], "fastcall")
		 
		const mmoo = VirtualAlloc(NULL, 0x1000, 0x1000, 4)
		//const mmoo = ptr(0x183b0000)
		console.log("MMoo:"+mmoo)
		
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
		xx2.putJmpAddress(Module.findBaseAddress('Game.dll').add(0x7E2FA5))
		xx2.flush()

		Memory.protect(mmoo,0x1000, 'rwx')
		// Game.dll+7E2FA0
		Memory.patchCode(Module.findBaseAddress('Game.dll').add(0x7E2FA0), 5, code => {
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
			
			const module = Process.getModuleByAddress(addr)
			const offset = addr.add(-module.base)
			//console.log(i + ",addr:" + addr + ",name:" + name + "\t" + param+"\t"+offset)
			allfuncs.push({
				name:name,
				dll:module.name,
				offset:offset,
				param:param,
				param_num:param_num
			})
			const hasn = itembase.add(0x14).readU32()
			if (hasn > 0x80000000) break;
			itembase = ptr(hasn)
		}
		//var ox = new File("D:\\Game\\__MQ\\kk_funs.txt", "w")
		//ox.write(JSON.stringify(allfuncs))
		//ox.flush()
		//ox.close()
		return allfuncs
	},
	call(name, ...p1)
	{
		this.init()
		if(!this._call_cache)
		{
			console.error("Jass 未初始化。先调用init")
			return
		}
		let callerObj = this._call_cache[name]
		if(!callerObj)
		{
			//GetLocalPlayer
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
			//console.log(JSON.stringify(f1))
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
			const dll = Process.findModuleByName(funcdefine.dll);
			if(!dll)
			{
				console.error(funcdefine.dll + " not loaded! " + name)
				return
			}
			const funcaddr = Process.findModuleByName(funcdefine.dll).base.add(funcdefine.offset)
			//console.log("funcadd:"+funcaddr)
			
			var par_out_2 = this.JassCallTypeConvert(par_out)
			const par_in_2 = [...par_in]
			for(let ii=0;ii<par_in_2.length;ii++)
			{
				par_in_2[ii] = this.JassCallTypeConvert(par_in_2[ii])
			}
			//console.log("in => " + JSON.stringify(par_in_2))
			//console.log("out => " + par_out)
			const caller = new NativeFunction(funcaddr, par_out_2, par_in_2, 'stdcall');
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
			
			if(type_==8)
			{
				//  exe print(jg.yaojingXGN__sjbez)
				//  exe print(jg.yaojingGG__wjid)
				//  exe local wjid =jg.yaojingGG__wjid print(wjid)
				//  exe print(jg.bj_FORCE_PLAYER[3])
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
						//console.log(luadata)
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


/////////////////////////////////////////////////////////////////////
//////////////////////////////扩展///////////////////////////////////
/////////////////////////////////////////////////////////////////////


//输入不了中文（函数中替换掉
function iptReplace(aa) {
	var ss = aa.readUtf8String()
	if(ss == '000'){
		aa.writeUtf8String("吃饭睡觉打豆豆")
	}else if(ss == '001'){
		aa.writeUtf8String("天天RPG")
	}else if(ss == 'mm'){
		aa.writeUtf8String("墨眉")
	}
}
function chatMsgReplace() {
	const Game_dll = Module.findBaseAddress('Game.dll')
	const getInputText = Game_dll.add(0x399630);

	Interceptor.attach(getInputText, {
		onEnter: function (args) {
		},
		onLeave: function (retval) {
			iptReplace(retval)
		}
	})
}
chatMsgReplace() 

jass.commonCallBack = (x)=>
{
	console.log("call commonCallBack:" + x)
	
	if(x == 2)
	{
		const player = jass.call('GetTriggerPlayer')
		const msg = jass.GetEventPlayerChatString()
		jass.call('DisplayTimedTextToPlayer',player,0,0,7,'|cffffcc00【金色】|r - |cffff0000【红色】|r - |cff339966【绿色】|r - |cff00ccff【蓝色】|r - |cffc0c0c0【灰色】|r - |cffff00ff【紫色】|r'+"-->"+msg)
		if(msg == ".")
		{
			//传送选中角色到鼠标位置
			jass.SetUnitPositionLoc(jass.DzGetSelectedLeaderUnit(),jass.Location(jass.DzGetMouseTerrainX(), jass.DzGetMouseTerrainY()))
		}
		else if(msg == "1")
		{
			//杀死选中对象
			//jass.KillUnit(jass.DzGetSelectedLeaderUnit());
			
			const g = jass.CreateGroup()
			jass.GroupEnumUnitsSelected(g, jass.GetTriggerPlayer(), null);
			const unit1 = jass.FirstOfGroup(g)
			jass.DestroyGroup(g)
			
			jass.KillUnit(unit1)
		}
		else if(msg == "11")
		{
			//杀死选中对象
			const target = jass.DzGetSelectedLeaderUnit()
			
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
			jass.UnitDamageTarget(actor, target, maxhp, false, true, ATTACK_TYPE_CHAOS, DAMAGE_TYPE_ENHANCED, null)
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
			jass.GroupEnumUnitsInRange(targetGroup, jass.DzGetMouseTerrainX(), jass.DzGetMouseTerrainY(), 1000, null)
			jass.ForGroup(targetGroup, ()=>{
				const curUnit = jass.GetEnumUnit()
				if(jass.IsUnitEnemy(curUnit,player))
				{
					console.log(" kill >> :" + jass.GetUnitName(curUnit))
					const maxhp = jass.GetUnitState(curUnit, UNIT_STATE_MAX_LIFE)
					jass.UnitDamageTarget(actor, curUnit, maxhp, false, true, ATTACK_TYPE_CHAOS, DAMAGE_TYPE_ENHANCED, null)
				}
			})
			jass.DestroyGroup(targetGroup)
			
		}
		else if(msg == "wd")
		{
			//选中对象无敌
			jass.SetUnitInvulnerable(jass.DzGetSelectedLeaderUnit(),true); 
		}
		else if(msg == "wd-")
		{
			//选中对象取消无敌
			jass.SetUnitInvulnerable(jass.DzGetSelectedLeaderUnit(),false);
		}
	}
}

function msghandle() {
	const t1 = jass.CreateTrigger()
	jass.TriggerRegisterPlayerChatEvent(t1, jass.Player(0), '', false)
	jass.TriggerAddAction(t1, 2)    
}
//进游戏后执行
//msghandle()


/////////////////////////////////////////////////////////////////////
/////////////////////////以下测试代码////////////////////////////////
/////////////////////////////////////////////////////////////////////
 


function Hook_Jass_load_save_Variant() {
	console.error("==========Hook_JassFuncs=============")

	
	return;
	Interceptor.attach(SaveInteger, {
		onEnter: function (args) {
			//if(args[1]!=0x1 && args[1]!=0x2 && args[1]!=0x1039c0 && args[2]!=0xcfde6c76 && args[2]!=0xece825e7)
			//{
			//console.log("SaveInteger ok:=====>"+args[0]+","+args[1]+","+args[2]+","+args[3]);
			//}
			//if(args[2]==0xa3098ae2)
			//{
			//	args[3]=ptr(0x1000)
			//}

		},
		onLeave: function (retval) {
		}
	});

	Interceptor.attach(LoadInteger, {
		onEnter: function (args) {
			//if(args[2]==0xDFB448FB)
			//console.log("LoadInteger ok:=====>"+args[0]+","+args[1]+","+args[2]+","+args[3]);

		},
		onLeave: function (retval) {
		}
	});

	Interceptor.attach(SaveReal, {
		onEnter: function (args) {
	
		},
		onLeave: function (retval) {
		}
	});
	Interceptor.attach(LoadStr, {
		onEnter: function (args) {
			//console.log("LoadStr:=====>"+args[0]);
			
		},
		onLeave: function (retval) {
			//console.log("???retval:"+retval.toString());
			//console.log('Context  : ' + JSON.stringify(this.context));
		}
	});
}
//Hook_Jass_load_save_Variant()


var War3Plugin = {
	RequestExtra__:0x9EEA0,
	DzAPI_Map_SaveServerValue:0x8be90,
	DzAPI_Map_GetServerValue:0x8beb0
}
function hook_RequestExtra()
{
	var War3PluginDll = Module.findBaseAddress('War3Plugin.dll')
	if(!War3PluginDll)
	{
		console.error("War3Plugin.dll不存在，跳过RequestExtraIntegerData")
		return
	}
/*	
	const RequestExtraIntegerData = War3PluginDll.add(War3Plugin.RequestExtra__)
	console.log("RequestExtraIntegerData:"+RequestExtraIntegerData)
	Interceptor.attach(RequestExtraIntegerData, {
		onEnter: function (args) {
			
			this.inparam = []
			for(let i=0;i<8;i++) this.inparam.push(args[i])
			return
			console.log("p0:"+args[0]+",p1:"+args[1]+",p2:"+args[2]+",p3:"+args[3]+",p4:"+args[4]+",p5:"+args[5]+",p6:"+args[6]+",p7:"+args[7])
			
			const keyname = jass.from_string(args[2])
			const value = args[3].add(8).readPointer().add(0x1c).readPointer().readCString()
			//if(args[0]==38)DzKeys.add(":I"+keyname)
			console.log("RequestExtraIntegerData:" + args[0] + ">>" + keyname + "=" + value)
		},
		onLeave: function (retval) {
			const args = this.inparam
			const keyname = jass.from_string(args[2])
			const value = jass.from_string(args[3])
			if(args[0] == 4)
			{
				console.log("RequestExtraIntegerData: Set int "+ keyname+"="+value +" >>>"+retval+":"+jass.getStringById(retval))
			}
			else if(args[0] == 5)
			{
				console.log("RequestExtraIntegerData: Get int "+ keyname+"="+value +" >>>"+retval+":"+jass.getStringById(retval))
			}
			else 
			{
				console.log("p0:"+args[0]+",p1:"+args[1]+",p2:"+args[2]+",p3:"+args[3]+",p4:"+args[4]+",p5:"+args[5]+",p6:"+args[6]+",p7:"+args[7])
				console.log("RequestExtraIntegerData:" + args[0] + ">>" + keyname + "=" + value + " >>>"+retval+":"+jass.getStringById(retval))
			}
		}
	});
*/

	const DzAPI_Map_SaveServerValue = War3PluginDll.add(War3Plugin.DzAPI_Map_SaveServerValue)
	console.log("DzAPI_Map_SaveServerValue:"+DzAPI_Map_SaveServerValue)
	Interceptor.attach(DzAPI_Map_SaveServerValue, {
		onEnter: function (args) {
			//(Hplayer;SS)B
			//console.log("p0:"+args[0]+",p1:"+args[1]+",p2:"+args[2])
			const keyname = jass.from_string(args[1])
			const value = jass.from_string(args[2])
			
			console.log("DzAPI_Map_SaveServerValue: "+args[0]+" "+ keyname+"="+value)
		},
		onLeave: function (retval) {
			
		}
	})	
	const DzAPI_Map_GetServerValue = War3PluginDll.add(War3Plugin.DzAPI_Map_GetServerValue)
	console.log("DzAPI_Map_GetServerValue:"+DzAPI_Map_GetServerValue)
	Interceptor.attach(DzAPI_Map_GetServerValue, {
		onEnter: function (args) {
			this.p0 = args[0]
			//(Hplayer;S)S
			//console.log("p0:"+args[0]+",p1:"+args[1]+",p2:"+args[2])
			this.keyname = jass.from_string(args[1])
		},
		onLeave: function (retval) {
			const value = jass.getStringById(retval)
			console.log("DzAPI_Map_GetServerValue: "+this.p0+" "+ this.keyname+"="+value)
		}
	})
	
}
hook_RequestExtra()
