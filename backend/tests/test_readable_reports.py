"""Readable exports must preserve evidence and existing role/filter boundaries."""
from datetime import datetime, timezone
from io import BytesIO
import zipfile
import pytest
from pypdf import PdfReader
from sqlalchemy import select
from app.models import HoneypotNode, HoneypotSession, SessionStatus, AttackCategory, AuditLog, UserRole

@pytest.fixture(autouse=True)
async def local_report_fixture(monkeypatch):
    from app.services import investigation_jobs
    from app.services.investigation_narrative import build_packet
    investigation_jobs.report_jobs.jobs.clear()
    async def generate(records):
        packet,_=build_packet(records);ref=packet['cases'][0]['reference']
        return {'summary':f'Demonstration explanation [{ref}]','findings':[{'title':'Demonstration explanation','paragraph':f'Demonstration explanation: the commands inspect the operating system [{ref}].','references':[ref],'quote':'whoami'}], 'assessment':f'No successful compromise is established [{ref}].','next_steps':f'Review recorded commands [{ref}].','scope':packet['scope'],'reviewed_references':[ref],'model':'test-local-model','generated_at':'2026-11-10T00:00:00Z'}
    monkeypatch.setattr(investigation_jobs,'generate_narrative',generate)
    yield
    investigation_jobs.report_jobs.jobs.clear()

@pytest.fixture
async def report_sessions(db_session):
    node=HoneypotNode(name='isolated-report-test',protocol='ssh',ip_address='192.0.2.10',port=2222)
    db_session.add(node);await db_session.flush()
    records=[]
    for i in range(2):
        record=HoneypotSession(node_id=node.id,session_uuid=f'demo-test-report-{i}',protocol='ssh',
            attacker_ip=f'192.0.2.{20+i}',attacker_port=40000+i,started_at=datetime.now(timezone.utc),
            status=SessionStatus.COMPLETED,attack_category=AttackCategory.RECONNAISSANCE,
            command_count=2,command_summary='SIMULATED: whoami; uname -a',model_source='rules',
            enrichment_status='complete',enrichment={'model':'demonstration-fixture','intent':'Demonstration explanation: the commands inspect identity and operating system.'})
        db_session.add(record);records.append(record)
    await db_session.commit()
    return records

async def test_pdf_and_word_contain_only_the_selected_session(client,auth_headers,report_sessions,db_session):
    headers=await auth_headers(UserRole.ANALYST)
    for fmt in ['pdf','docx']:
        response=await client.post(f'/api/v1/export/?format={fmt}&session_ids={report_sessions[0].id}',headers=headers)
        assert response.status_code==200,response.text[:200]
        assert response.headers['x-export-count']=='1'
        assert response.headers['x-export-truncated']=='false'
        assert f'.{fmt}' in response.headers['content-disposition']
        if fmt=='pdf':
            assert response.headers['content-type']=='application/pdf'
            text=' '.join(page.extract_text() for page in PdfReader(BytesIO(response.content)).pages)
            for expected in ['192.0.2.20','What happened','Demonstration explanation','SIMULATED DEMONSTRATION']:assert expected in text
            assert '192.0.2.21' not in text
        else:
            from docx import Document
            doc=Document(BytesIO(response.content))
            assert any('Demonstration explanation' in p.text for p in doc.paragraphs)
            with zipfile.ZipFile(BytesIO(response.content)) as z:assert any(n.startswith('word/media/') for n in z.namelist())
    audits=(await db_session.execute(select(AuditLog).where(AuditLog.action=='sessions_exported'))).scalars().all()
    assert len(audits)==2

async def test_viewer_and_anonymous_cannot_download_readable_reports(client,auth_headers,report_sessions):
    headers=await auth_headers(UserRole.VIEWER)
    for fmt in ['pdf','docx']:
        denied=await client.post(f'/api/v1/export/?format={fmt}',headers=headers)
        assert denied.status_code==403
        anonymous=await client.post(f'/api/v1/export/?format={fmt}')
        assert anonymous.status_code in [401,403]

async def test_pdf_selection_limit_and_no_matches(client,auth_headers,report_sessions):
    headers=await auth_headers(UserRole.ADMIN)
    for fmt in ['pdf','docx']:
        many=await client.post('/api/v1/export/?format='+fmt+'&'+'&'.join(f'session_ids={n}' for n in range(101)),headers=headers)
        assert many.status_code==400
        empty=await client.post(f'/api/v1/export/?format={fmt}&search=does-not-match-any-record',headers=headers)
        assert empty.status_code==404

async def test_existing_exports_still_work(client,auth_headers,report_sessions):
    headers=await auth_headers(UserRole.ANALYST)
    for fmt in ['csv','json','cef','stix']:
        res=await client.post(f'/api/v1/export/?format={fmt}',headers=headers)
        assert res.status_code==200
        assert res.headers['x-export-count']=='2'
