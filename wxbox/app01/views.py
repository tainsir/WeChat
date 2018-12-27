import json
import functools
import requests
from django.conf import settings
from django.shortcuts import render, redirect, HttpResponse
from django.http import JsonResponse
from app01 import models
# 沙箱环境地质：https://mp.weixin.qq.com/debug/cgi-bin/sandbox?t=sandbox/login
def index(request):
    obj = models.UserInfo.objects.get(id=1)
    return render(request,'index.html',{'obj':obj})


def auth(func):
    def inner(request, *args, **kwargs):
        user_info = request.session.get('user_info')
        if not user_info:
            return redirect('/login/')
        return func(request, *args, **kwargs)

    return inner


def login(request):
    """
    用户登录
    :param request: 
    :return: 
    """
    # models.UserInfo.objects.create(username='luffy',password=123)

    if request.method == "POST":
        user = request.POST.get('user')
        pwd = request.POST.get('pwd')
        obj = models.UserInfo.objects.filter(username=user, password=pwd).first()
        if obj:
            request.session['user_info'] = {'id': obj.id, 'name': obj.username, 'uid': obj.uid}
            return redirect('/bind/')
    else:
        return render(request, 'login.html')


@auth
def bind(request):
    """
    用户登录后，关注公众号，并绑定个人微信（用于以后消息推送）
    :param request: 
    :return: 
    """
    return render(request, 'bind.html')


@auth
def bind_qcode(request):
    """
    生成二维码
    :param request: 
    :return: 
    """
    ret = {'code': 1000}
    try:
        # 微信官方文档接口
        access_url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid={appid}&redirect_uri={redirect_uri}&response_type=code&scope=snsapi_userinfo&state={state}#wechat_redirect"
        access_url = access_url.format(
            # 商户的appid
            appid=settings.WECHAT_CONFIG["app_id"], # 'wx6edde7a6a97e4fcd',
            # 回调地址
            redirect_uri=settings.WECHAT_CONFIG["redirect_uri"],
            # 当前登录用户的唯一id
            state=request.session['user_info']['uid'] # 为当前用户生成MD5值
        )
        ret['data'] = access_url
    except Exception as e:
        ret['code'] = 1001
        ret['msg'] = str(e)

    return JsonResponse(ret)


def callback(request):
    """
    用户在手机微信上扫码后，微信自动调用该方法。
    用于获取扫码用户的唯一ID，以后用于给他推送消息。
    :param request: 
    :return: 
    """
    code = request.GET.get("code")

    # 用户md5值,用户唯一id
    state = request.GET.get("state")

    # 获取该用户openId(用户唯一，用于给用户发送消息)
    # request模块朝https://api.weixin.qq.com/sns/oauth2/access_token地址发get请求
    # res是转成json格式的字典
    res = requests.get(
        url="https://api.weixin.qq.com/sns/oauth2/access_token",
        params={
            "appid": 'wx3e1f0883236623f9',
            "secret": '508ec4590702c76e6863be6df01ad95a',
            "code": code,
            "grant_type": 'authorization_code',
        }
    ).json()
    # res.data   是json格式
    # res=json.loads(res.data)
    # res是一个字典
    # 获取的到openid表示用户授权成功
    # openid就是微信号的id
    openid = res.get("openid")
    if openid:
        models.UserInfo.objects.filter(uid=state).update(wx_id=openid)
        response = "<h1>授权成功 %s </h1>" % openid
    else:
        response = "<h1>用户扫码之后，手机上的提示</h1>"
    return HttpResponse(response)


def sendmsg(request):
    def get_access_token():
        """
        获取微信全局接口的凭证(默认有效期俩个小时)
        如果不每天请求次数过多, 通过设置缓存即可
        """
        result = requests.get(
            url="https://api.weixin.qq.com/cgi-bin/token",
            params={
                "grant_type": "client_credential",
                "appid": settings.WECHAT_CONFIG['app_id'],
                "secret": settings.WECHAT_CONFIG['appsecret'],
            }
        ).json()
        if result.get("access_token"):
            access_token = result.get('access_token')
        else:
            access_token = None
        return access_token

    access_token = get_access_token()

    openid = models.UserInfo.objects.get(id=1).wx_id

    def send_custom_msg():
        body = {
            "touser": openid,
            "msgtype": "text",
            "text": {
                "content": 'lqz大帅哥'
            }
        }
        response = requests.post(
            url="https://api.weixin.qq.com/cgi-bin/message/custom/send",
            # 放到路径?后面的东西
            params={
                'access_token': access_token
            },
            # 这是post请求body体中的内容
            data=bytes(json.dumps(body, ensure_ascii=False), encoding='utf-8')
        )
        # 这里可根据回执code进行判定是否发送成功(也可以根据code根据错误信息)
        result = response.json()
        return result

    def send_template_msg():
        """
        发送模版消息
        """
        res = requests.post(
            url="https://api.weixin.qq.com/cgi-bin/message/template/send",
            params={
                'access_token': access_token
            },
            json={
                "touser": openid,
                "template_id": 'IaSe9s0rukUfKy4ZCbP4p7Hqbgp1L4hG6_EGobO2gMg',
                "data": {
                    "first": {
                        "value": "lqz",
                        "color": "#173177"
                    },
                    "keyword1": {
                        "value": "大帅哥",
                        "color": "#173177"
                    },
                }
            }
        )
        result = res.json()
        return result

    result = send_custom_msg()

    if result.get('errcode') == 0:
        return HttpResponse('发送成功')
    return HttpResponse('发送失败')
