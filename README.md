# War3(Warcraft III)作弊器
基于 [Frida](https://frida.re/) 的作弊器引擎。可以执行Jass函数，修改Jass变量。使用Jass增加游戏扩展功能。


## 使用的先决条件
* 你必须知道 Frida 是什么，以及会安装 Frida。
* 你至少得略懂 Jass 语言。


## 支持的版本
* 1.27.0.52240


## 执行Jass函数
```jass.GetPlayers()```
或者
```jass.call("GetPlayers")```



## 全局变量

访问

```jass.getGlobalVariable("DAMAGE_TYPE_ACID")```


修改

```jass.getGlobalVariable("DAMAGE_TYPE_ACID").setvalue(1)```