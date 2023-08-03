# 泛微ofslogin.jsp任意用户登录&changeuserinfo.jsp信息泄漏漏洞组合利用工具

# 本工具仅供学习测试使用，请勿用于非法用途！！



## 使用

使用前安装依赖

```
pip install -r requirements.txt
```

1.单个目标爆破loginId并测试ofslogin任意用户登录漏洞

```sh
python3 ecology_ofsLogin_brute.py -u url
```

2.多个目标爆破loginId并测试ofslogin任意用户登录漏洞(为快速测试，ofslogin漏洞仅测试一次，之后进入下一个url)

```sh
python3 ecology_ofsLogin_brute.py -f file.txt
```

3.仅爆破loginId(单个目标)

```sh
python3 ecology_ofsLogin_brute.py -u url --brute --loginId
```

4.仅爆破loginId(多个目标)

```sh
python3 ecology_ofsLogin_brute.py -f file.txt --brute --loginId
```

5.仅爆破ofslogin漏洞(单个目标)

```sh
python3 ecology_ofsLogin_brute.py -u url -l loginid.txt --brute --ofsLogin
```

6.仅爆破ofslogin漏洞(多个目标)

```sh
python3 ecology_ofsLogin_brute.py -f file.txt -l loginid.txt --brute --ofsLogin
```

## 示例

因为是通过mobile模糊查询遍历，会有重复的loginId

![image-20230602161412416](https://github.com/A0WaQ4/Weaver_ofslogin_vul/blob/main/img/image-20230602161412416.png)

爆破成功后会自动生成`loginid.txt`和`result.txt`文件，用于保存爆破出的`loginId`和`ofslogin`漏洞结果	

![image-20230602161418855](https://github.com/A0WaQ4/Weaver_ofslogin_vul/blob/main/img/image-20230602161418855.png)

