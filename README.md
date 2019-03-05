Real-time Control Protocol(RTCP) Fuzzer Tools 
===


# Description
針對即時傳輸控制協定(RTCP)所開發的自動化模糊測試工具
本工具適用於Linux、Windows、MacOS作業系統上執行
建議使用Python 2.7.x環境執行
下載後，目錄內會以下四個檔案


* README.md 說明檔
* LOG.TXT 執行後測試過程的日誌檔
* rtcp.conf 參數設定檔
* rtcpfuzz.py 檢測程式


測試目的為造成Server端在解析封包過程中發生錯誤，造成設備重新開機或其他異常行為，驗證IoT設備是否存在被Client端所發出的封包造成服務中斷的弱點。


# Features
針對RTCP協定中SR(Sender、Report)、RR(Receive Report)、SDES(Source Description)、BYE、APP 五種Packet定義的封包格式對各欄位增加額外隨機產生的字元進行測試，例如'NTP timestamp MSW'、'NTP timestamp LSW'、'SDES items'等多項欄位進行Fuzzing Test



# Usage
## Step1:設定參數檔rtcp.conf
1.RHOST改成設備IP address
2.RPORT為RTCP的服務PORT。(根據標準,基本上RTCP port會是RTP Port+1)
3.JUNK和DELAY欄位使用預設即可。
4.MSFPATTERN保持預設為ON不需更改，此模式為讓模糊測試執行時會隨機產生payload，就不會只產生不同數量的JUNK字元(ex.AAAAAAAAAAAA)
5.STOPAFTER為模糊測試的測試筆數，規範門檻為10萬筆。

Example:
```bash=
[rtcpfuzz]
#IP or Host name of the Remote host
RHOST : 192.168.1.56

#RTCP Service port Default is RTP_PORT_number + 1
RPORT : 51001

#Junk Bytes to USE (Don't use more than one character at a time like AAAA   BBBB).
JUNK : A

#Time Delay in Seconds between two requests 
DELAY : 0

#Use Metasploit pattern for fuzzing
#if its ON then it will use metasploit pattern as junk data for fuzzing instead of AAA/BBB etc etc
#using metasploit pattern when fuzzing helps to find offset
#Warning:Turning this feature on may take some extra time for fuzzing.

MSFPATTERN : ON
# terminate value
STOPAFTER : 1000000
```


## STEP2
將參數檔設定完畢後，即可開始執行程式。
```
python rtcpfuzz.py
```
## STEP3
程式執行完成後

打開log.txt確認測試過程中完整性，檢查測試筆數是否有達到10萬筆或八小時的標準

# Reference
ITEF RFC-3550文件:https://tools.ietf.org/html/rfc3550