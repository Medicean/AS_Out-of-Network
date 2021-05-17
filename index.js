
'use strict';

const WIN = require('ui/window'); // 窗口库
const tabbar = require('ui/tabbar'); // Tab库
const LANG_T = antSword['language']['toastr']; // 通用通知提示

const LANG = require('./language/'); // 插件语言库
/**
 * 插件类
*/
class Plugin {
  constructor(opt) {
    let self = this;
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
        { id: 'start', type: 'button', text: LANG['toolbar']['start'], icon: 'play',}, // 开始按钮
        { id: 'reset', type: 'button', text: LANG['toolbar']['reset'], icon: 'undo',}, // 重置按钮
    ]);
    self.toolbar = toolbar;
    // 点击事件
    toolbar.attachEvent('onClick', (id)=>{
    switch(id){
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

  // 自定义函数,用于获取不同类型的 payload
  getPayload(shelltype){
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
        $ips = ['220.181.38.148', '39.156.69.79', 'www.baidu.com'];
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
        echo "[+][UDP][Fail][8.8.8.8:53]\\n";
      }
      checkDNS("qq.com");
      `,
      asp: '',
      aspx: ''
    }
    return codes[shelltype];
  }
}

module.exports = Plugin;