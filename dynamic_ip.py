__author__ = 'Oscar Yang Liu'

import json, time

from PyQt5.QtCore import QTimer, QSettings, QEvent
from PyQt5.QtGui import QIntValidator, QIcon
from PyQt5.QtNetwork import QLocalSocket, QLocalServer
from PyQt5.QtWidgets import QApplication, QWidget, QMessageBox, QSystemTrayIcon, QMenu, QAction
from resource.UI.main import Ui_main
from common.descryptandencrypt import PasswordHandle
from common.requestools import AsyncRequest



class DynamicIp(QWidget,Ui_main):
  def __init__(self, parent=None, *args, **kwargs):
    super().__init__(parent, *args, **kwargs)
    self.initUi()

  def initUi(self):
    self.setupUi(self)
    # 先取保存的变量
    self.settings = QSettings("yqfsoft", "DDNS")
    self.userinfo = self.settings.value('userinfo')
    # 开机自动启动
    self.load_autorun_setting()
    # 设置文本可以跳转页面
    self.web_lb.setOpenExternalLinks(True)
    # 读取userinfo
    self.load_userinfo()
    # 创建托盘
    self.create_tuopan()
    self.ip_request = AsyncRequest()
    # self.update_ip_request = AsyncRequest()
    # 获取ip地址
    # https://ipv4.jsonip.com https://ipv6.jsonip.com https://jsonip.com
    self.ip_url = 'https://ipv4.jsonip.com'
    self.ip_request.get(self.ip_url)

    # dyndns更新
    self.request_ip_time = QTimer()

    # 验证时间的
    update_time_validator = QIntValidator(5, 1092)
    self.update_time_le.setValidator(update_time_validator)

    # 信号
    # 获取ip地址的信号
    self.ip_request.getResult.connect(self.get_ip_result)
    # dyndns发送更新ip地址
    # self.update_ip_request.getResult.connect(self.get_update_ip_result)
    self.request_ip_time.timeout.connect(lambda: self.ip_request.get(self.ip_url))
    # 监控托盘的双击显示和隐藏
    self.tuopan.activated[self.tuopan.ActivationReason].connect(self.iconActivated)

  # 开启同步绑定ip服务
  def start_update_ip(self):
    if self.ip_lb.text() == '':
      return None
    domain = self.domain_le.text()
    username = self.username_le.text()
    password = self.password_le.text()
    if domain == '' or username == '' or password == '':
      return None
    if self.update_time_le.text() == '' or int(self.update_time_le.text())<5 or int(self.update_time_le.text())>1092:
      self.update_time_le.setText('5')
    update_time = self.update_time_le.text()
    if domain != '' and username != '' and password != '' and update_time != '':
      # 密码加密保存到注册表
      encrypt_password = PasswordHandle.encrypt(password)
      self.is_connected(True)
      self.userinfo = {'domain': domain, 'username': username, 'password': encrypt_password,
                       'update_time': update_time, 'editable': self.ok_btn.isEnabled()}
      self.settings.setValue('userinfo', self.userinfo)
    # 发送更新请求
    self.ip_request.get(self.ip_url)

  def edit_info(self):
    self.is_connected(False)
    self.userinfo['editable'] = True
    self.settings.setValue('userinfo', self.userinfo)

  # 服务启动设施禁用
  def is_connected(self, state: bool):
    self.domain_le.setDisabled(state)
    self.username_le.setDisabled(state)
    self.password_le.setDisabled(state)
    self.update_time_le.setDisabled(state)
    self.ok_btn.setDisabled(state)

  # toggle 开机是否启动
  def is_start_in_window(self, toggle):
    if toggle:
      # 执行开机自动启动方法
      self.autorun_setting.setValue('DynamicIp',  sys.argv[0])
    else:
      # 不执行开机自动启动方法
      self.autorun_setting.remove('DynamicIp')

  # 读取开机自动启动配置
  def load_autorun_setting(self):
    self.autorun_regedit_path = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
    self.autorun_setting = QSettings(self.autorun_regedit_path, QSettings.NativeFormat)
    self.window_startup_cb.setChecked(self.autorun_setting.contains('DynamicIp'))
    if self.autorun_setting.contains('DynamicIp'):
      if self.autorun_setting.value('DynamicIp') != sys.argv[0]:
        self.autorun_setting.value.setValue('DynamicIp', sys.argv[0])
      if not self.ok_btn.isEnabled():
        self.hide()


  # 读取保存的userinfo
  def load_userinfo(self):
    if self.settings.contains('userinfo'):
      self.domain_le.setText(self.userinfo['domain'])
      self.username_le.setText(self.userinfo['username'])
      self.password_le.setText(PasswordHandle.descrypt(self.userinfo['password']))
      self.update_time_le.setText(self.userinfo['update_time'])
      self.is_connected(not self.userinfo['editable'])

  # 创建托盘
  def create_tuopan(self):
    # 托盘
    self.tuopan = QSystemTrayIcon(self)  # 创建托盘
    self.tuopan.setIcon(QIcon(':/img/img/ip.jpg'))  # 设置托盘图标
    # 创建托盘的右键菜单
    tpMenu = QMenu()
    a1 = QAction(u'Show', self, triggered=self.restore_display)
    a2 = QAction(u'Exit', self, triggered=self.close)
    tpMenu.addAction(a1)
    tpMenu.addAction(a2)
    self.tuopan.setContextMenu(tpMenu)  # 把tpMenu设定为托盘的右键菜单
    # 设置提示信息
    self.tuopan.setToolTip(u'Dynamic ip')
    self.tuopan.show()

  # 获取ip执行的方法
  def get_ip_result(self, dic):
    # 判断返回值字典中有没有ip这个健 如果没有表示没有获取到ip
    result = json.loads(dic['result'])
    if 'ip' in result:
      self.ip_lb.setText(result['ip'])
      if not self.ok_btn.isEnabled():
        username = self.username_le.text()
        password = self.password_le.text()
        domain = self.domain_le.text()
        try:
          self.update_ip(username, password, domain, result['ip'])
          self.error_info_lb.setText('')
        except:
          self.error_info_lb.setText('Update ip failed')
    else:
      self.ip_lb.setText('')
    self.request_ip_time.start(int(self.update_time_le.text()) * 60 * 1000)

  # 向dyndns发送api后的返回值
  # def get_update_ip_result(self, dic):
  #   # 返回结果如果有ip地址说明成功 如果返回的字符串中‘.’出现3次我就认为更新成功 ip地址会出现3个‘.’
  #   print(dic['result'])
  #   if dic['result'].count('.') == 3:
  #     print('修改地址成功')

  # 托盘中恢复显示的方法
  def restore_display(self):
    self.showNormal()
    self.activateWindow()

  # 更新ip
  # DynDns Api
  # self.update_ip_url = 'https://username:password@members.dyndns.org/v3/update'
  # self.get(self.update_ip_url,{'hostname':'域名','myip':'当前的ip地址'})
  # self.update_ip(bytes_to_json['ip'])
  def update_ip(self, username: str, password: str, domain: str, new_ip: str):
    url = 'https://{}:{}@members.dyndns.org/v3/update'.format(username, password)
    self.update_ip_request.get(url, {'hostname': domain, 'myip': new_ip})

  # 托盘图标事件
  def iconActivated(self, reason):
    if reason == self.tuopan.Trigger:
      self.showNormal()
      self.activateWindow()

  # 最小化 事件
  def event(self, event):
    super().event(event)
    if event.type() == QEvent.WindowStateChange:
      if self.isMinimized():
        self.hide()
    return False


  # 退出程序保存
  def closeEvent(self, event):
    reply = QMessageBox.question(self, 'Dynamic ip', "Are you sure to exit?",
                                 QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
    # 判断返回值，如果点击的是Yes按钮，我们就关闭组件和应用，否则就忽略关闭事件
    if reply == QMessageBox.Yes:
      # 退出保存变量
      domain = self.domain_le.text()
      username = self.username_le.text()
      password = self.password_le.text()
      if self.update_time_le.text() == '' or int(self.update_time_le.text())<5 or int(self.update_time_le.text())>1092:
        self.update_time_le.setText('5')
      update_time = self.update_time_le.text()
      encrypt_password = PasswordHandle.encrypt(password)
      self.userinfo = {'domain': domain, 'username': username, 'password': encrypt_password,
                       'update_time': update_time, 'editable': self.ok_btn.isEnabled()}
      self.settings.setValue('userinfo', self.userinfo)
      event.accept()
    else:
      event.ignore()

if __name__ == '__main__':
  # 只允许一个程序启动
  try:
    import sys
    app = QApplication(sys.argv)
    serverName = 'yqfSoftDDNStestServer'
    socket = QLocalSocket()
    socket.connectToServer(serverName)
    # 如果连接成功，表明server已经存在，当前已有实例在运行
    if socket.waitForConnected(500):
      app.quit()
    else:
      localServer = QLocalServer()  # 没有实例运行，创建服务器
      localServer.listen(serverName)
      # 处理其他事务
      window = DynamicIp()
      window.show()
      sys.exit(app.exec_())
  except:
    pass
