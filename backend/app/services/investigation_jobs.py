"""Bounded, owner-scoped report jobs for the single dashboard API process."""
from __future__ import annotations
import asyncio,hashlib,json,time
from uuid import uuid4
from starlette.concurrency import run_in_threadpool
from app.services.investigation_narrative import generate_narrative,NarrativeUnavailable
from app.services.pdf_report import generate_pdf_report

class JobsFull(Exception):pass
class ReportJobs:
 TTL=1800
 MAX_JOBS=6
 def __init__(self):
  self.jobs={};self.slot=asyncio.Semaphore(1);self.render_slot=asyncio.Semaphore(2)
 def prune(self):
  now=time.monotonic()
  for key,job in list(self.jobs.items()):
   if job['task'].done() and now-job['touched']>self.TTL:self.jobs.pop(key,None)
 def submit(self,owner,records,sensitive=False):
  self.prune()
  signature=hashlib.sha256(json.dumps([records,bool(sensitive)],sort_keys=True,ensure_ascii=False,default=str).encode()).hexdigest()
  for job in self.jobs.values():
   if job['owner']==owner and job['signature']==signature and job['status']!='failed':job['touched']=time.monotonic();return job
  if sum(not j['task'].done() for j in self.jobs.values())>=2:raise JobsFull('Two reports are already being prepared. Please wait for one to finish.')
  if len(self.jobs)>=self.MAX_JOBS:
   completed=[j for j in self.jobs.values() if j['task'].done()]
   if not completed:raise JobsFull('Report generation is busy. Please retry shortly.')
   self.jobs.pop(min(completed,key=lambda j:j['touched'])['id'])
  job={'id':str(uuid4()),'owner':owner,'signature':signature,'records':records,'sensitive':bool(sensitive),'status':'queued','message':'Waiting for the local analysis model.','error':None,'narrative':None,'files':{},'touched':time.monotonic()}
  self.jobs[job['id']]=job;job['task']=asyncio.create_task(self._write(job),name='investigation-'+job['id']);return job
 async def _write(self,job):
  try:
   async with self.slot:
    job.update(status='analysing',message='Our local model is writing findings from the selected evidence. This can take several minutes.')
    job['narrative']=await generate_narrative(job['records'])
    job.update(status='complete',message='The investigation is ready to download.')
  except asyncio.CancelledError:
   job.update(status='failed',error='Report generation was interrupted. Please generate it again.');raise
  except NarrativeUnavailable as exc:job.update(status='failed',error=str(exc))
  except Exception:job.update(status='failed',error='The investigation could not be prepared. Please retry; no generic report was substituted.')
  finally:job['touched']=time.monotonic()
 def owned(self,identity,owner):
  self.prune();job=self.jobs.get(identity)
  if not job or job['owner']!=owner:raise KeyError(identity)
  job['touched']=time.monotonic();return job
 @staticmethod
 def status(job):
  return {'id':job['id'],'status':job['status'],'message':job['error'] if job['status']=='failed' else job['message'],'session_count':len(job['records']),'include_sensitive':job['sensitive'],'model':(job.get('narrative') or {}).get('model')}
 async def render(self,job,format):
  if job['status']!='complete':raise NarrativeUnavailable(job['error'] or 'The local model is still preparing this report.')
  if format not in job['files']:
   async with self.render_slot:
    if format not in job['files']:
     job['files'][format]=await run_in_threadpool(generate_pdf_report,job['records'],format,job['narrative'],job['sensitive'])
  return job['files'][format]

report_jobs=ReportJobs()
