from pathlib import Path
from html.parser import HTMLParser
import http.cookiejar,json,re,urllib.error,urllib.parse,urllib.request

class Forms(HTMLParser):
 def __init__(self,body):
  super().__init__();self.forms=[];self.current=None;self.feed(body.decode(errors='replace'))
 def handle_starttag(self,tag,attrs):
  attrs=dict(attrs)
  if tag=='form':self.current={'attrs':attrs,'fields':{},'textareas':[]};self.forms.append(self.current)
  elif self.current is not None and tag=='input' and attrs.get('name') and attrs.get('type','').lower()in ['hidden','text','email']:
   self.current['fields'][attrs['name']]=attrs.get('value','')
  elif self.current is not None and tag=='textarea' and attrs.get('name'):self.current['textareas'].append(attrs['name'])
 def handle_endtag(self,tag):
  if tag=='form':self.current=None

class Client:
 def __init__(self,name,runtime,report,save):
  self.name=name;self.runtime=runtime;self.report=report;self.save=save;self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def request(self,label,path,fields=None):
  req=urllib.request.Request(self.runtime['base']+path,data=urllib.parse.urlencode(fields).encode()if fields is not None else None,headers={'User-Agent':'module-target-native-control'})
  try:r=self.opener.open(req,timeout=90)
  except urllib.error.HTTPError as error:r=error
  with r:body=r.read();status=r.status;headers=dict(r.headers);url=r.url
  file=self.name+'-'+label+'.body';(Path(self.runtime['directory'])/file).write_bytes(body);self.report['requests'].append({'client':self.name,'label':label,'path':path,'method':req.get_method(),'status':status,'url':url,'headers':headers,'file':file,'bytes':len(body)});self.save();return status,body
 def token(self,body):
  for form in Forms(body).forms:
   if '__CSRFToken__'in form['fields']:return form['fields']['__CSRFToken__']
  raise AssertionError('No genuine CSRF field')
