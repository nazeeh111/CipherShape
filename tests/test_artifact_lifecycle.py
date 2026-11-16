"""Disposable marker-only lifecycle and transport tests; no cryptographic claim."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from ciphershape import artifacts as art, api, cli


def payloads(files=None):
    files = files or {'0.bin': b'synthetic-ciphertext'}
    env = {'version':1,'program_id':'program','epoch':'epoch','context_id':'context',
           'request_id':'request','ciphertexts':{k:hashlib.sha256(v).hexdigest() for k,v in files.items()}}
    return env, {'envelope':env,'files':{k:base64.b64encode(v).decode() for k,v in files.items()},'server_metadata':{}}


def complete(stage):
    for role, directory in stage.items(): (directory/'marker').write_text('owned-'+role)


def test_real_exclusive_rename_and_late_collision_preserves_competitor(tmp_path):
    src=tmp_path/'src';src.mkdir();(src/'owned').write_text('ours')
    dest=tmp_path/'dest';dest.mkdir();(dest/'theirs').write_text('theirs')
    with pytest.raises(OSError):art._rename_new(src,dest)
    assert (dest/'theirs').read_text()=='theirs' and (src/'owned').read_text()=='ours'
    target=tmp_path/'late'
    with pytest.raises(OSError):
        with art.staged_artifacts('request',request=target) as stage:
            complete(stage);target.mkdir();(target/'theirs').write_text('competitor')
    assert (target/'theirs').read_text()=='competitor'


def interrupted_setup(root, n):
    script='''import os,sys\nfrom pathlib import Path\nfrom ciphershape import artifacts as a\nroot=Path(sys.argv[1]); n=int(sys.argv[2]); original=a._rename_new; count=[0]\ndef crash(src,dst):\n original(src,dst);count[0]+=1\n if count[0]==n: os._exit(71)\na._rename_new=crash\ndef prepared(j): (root/'journal-path').write_text(str(j))\nwith a.staged_artifacts('setup',private=root/'private',public=root/'public',on_prepared=prepared) as st:\n (st['private']/'marker').write_text('private marker');(st['public']/'marker').write_text('public marker')\n'''
    p=subprocess.run([sys.executable,'-c',script,str(root),str(n)],env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')},capture_output=True,text=True,timeout=15)
    assert p.returncode==71,(p.stdout,p.stderr)
    return Path((root/'journal-path').read_text())


def test_killed_after_first_rename_rolls_back_only_unchanged_private(tmp_path):
    journal=interrupted_setup(tmp_path,1); assert (tmp_path/'private/marker').read_text()=='private marker'
    assert art.recover_artifacts(journal)['state']=='aborted'
    assert not (tmp_path/'private').exists() and not (tmp_path/'public').exists()
    with art.staged_artifacts('setup',private=tmp_path/'private',public=tmp_path/'public') as stage: complete(stage)
    assert (tmp_path/'public/marker').read_text()=='owned-public'


def test_killed_after_commit_then_moved_public_preserves_private_and_journal(tmp_path):
    journal=interrupted_setup(tmp_path,2);(tmp_path/'public').rename(tmp_path/'moved-public')
    with pytest.raises(art.ProtocolError,match='indeterminate'):art.recover_artifacts(journal)
    assert (tmp_path/'private/marker').read_text()=='private marker'
    assert (tmp_path/'moved-public/marker').read_text()=='public marker' and journal.exists()


def test_killed_first_rename_changed_private_is_preserved(tmp_path):
    journal=interrupted_setup(tmp_path,1); marker=tmp_path/'private/marker';marker.write_text('user-modified')
    with pytest.raises(art.ProtocolError):art.recover_artifacts(journal)
    assert marker.read_text()=='user-modified' and journal.exists()


def test_active_and_replaced_journal_refuse_recovery(tmp_path):
    target=tmp_path/'out'
    with art.staged_artifacts('request',request=target) as stage:
        complete(stage); journal=stage['request'].parent/'stage.json'
        with pytest.raises(art.ProtocolError,match='active'):art.recover_artifacts(journal)
    assert (target/'marker').read_text()=='owned-request'


def test_changed_journal_inode_never_recovers(tmp_path,monkeypatch):
    journal=interrupted_setup(tmp_path,1); old=journal.with_name('old-journal'); data=journal.read_bytes()
    original=art._read_fd
    def replace(fd,limit):
        raw=original(fd,limit);journal.rename(old);journal.write_bytes(data);journal.chmod(0o600);return raw
    monkeypatch.setattr(art,'_read_fd',replace)
    with pytest.raises(art.ProtocolError,match='changed'):art.recover_artifacts(journal)
    assert (tmp_path/'private/marker').read_text()=='private marker' and old.exists() and journal.exists()


def test_bounded_regular_members_and_fifo(tmp_path):
    fifo=tmp_path/'fifo';os.mkfifo(fifo)
    with pytest.raises(art.ProtocolError):art.read_bytes(fifo,100)
    oversized=tmp_path/'big';oversized.write_bytes(b'x'*101)
    with pytest.raises(art.ProtocolError):art.read_bytes(oversized,100)
    folder=tmp_path/'many';folder.mkdir()
    for n in range(art.MAX_MEMBERS+1): (folder/str(n)).write_bytes(b'x')
    with pytest.raises(art.ProtocolError,match='member'):art._tree(folder)


@pytest.mark.parametrize('failures',[1,2])
def test_cleanup_failure_once_succeeds_twice_returns_recoverable_commit(tmp_path,monkeypatch,failures):
    target=tmp_path/'final';actual=art._settle;calls=[]; journal=[]
    def flaky(record,path):
        calls.append(1)
        if len(calls)<=failures:raise OSError('synthetic cleanup fault')
        return actual(record,path)
    monkeypatch.setattr(art,'_settle',flaky)
    if failures==1:
        with art.staged_artifacts('request',request=target,on_prepared=journal.append) as stage:complete(stage)
        assert (target/'marker').read_text()=='owned-request' and not journal[0].exists()
    else:
        with pytest.raises(art.CleanupPending) as error:
            with art.staged_artifacts('request',request=target,on_prepared=journal.append) as stage:complete(stage)
        assert error.value.journal==journal[0] and (target/'marker').read_text()=='owned-request'
        monkeypatch.setattr(art,'_settle',actual)
        assert art.recover_artifacts(journal[0])['state']=='committed'
        assert (target/'marker').read_text()=='owned-request'


def test_pack_and_unpack_actual_bytes_no_clobber_and_same_snapshot(tmp_path,monkeypatch):
    env,body=payloads();directory=tmp_path/'request';directory.mkdir()
    (directory/'0.bin').write_bytes(b'synthetic-ciphertext');(directory/'envelope.json').write_text(json.dumps(env))
    real=api.read_bytes
    def capture(path,limit,**kw):
        value=real(path,limit,**kw)
        if str(path)=='0.bin':(directory/'0.bin').write_bytes(b'changed after read')
        return value
    monkeypatch.setattr(api,'read_bytes',capture)
    packed=api.pack(directory); decoded=json.loads(packed)
    assert base64.b64decode(decoded['files']['0.bin'])==b'synthetic-ciphertext'
    out=tmp_path/'out';api.unpack(packed,out,100000,expected=env,count=1,request_id='request')
    assert (out/'0.bin').read_bytes()==b'synthetic-ciphertext'
    with pytest.raises((art.ProtocolError,FileExistsError)):api.unpack(packed,out,100000,expected=env,count=1)
    assert (out/'0.bin').read_bytes()==b'synthetic-ciphertext'


@pytest.mark.parametrize('mutation',['traversal','digest','epoch','context','program','request','count','telemetry','symlink'])
def test_invalid_transport_is_refused_before_publication(tmp_path,mutation):
    env,body=payloads(); expected=dict(env)
    if mutation=='traversal':body['files']['../marker']=body['files'].pop('0.bin');body['envelope']['ciphertexts']['../marker']=body['envelope']['ciphertexts'].pop('0.bin')
    if mutation=='digest':body['files']['0.bin']=base64.b64encode(b'altered').decode()
    if mutation in ('epoch','context','program'):body['envelope'][{'epoch':'epoch','context':'context_id','program':'program_id'}[mutation]]='different'
    if mutation=='request':body['envelope']['request_id']='different'
    if mutation=='telemetry':body['server_metadata']={'accepted':True}
    out=tmp_path/'destination'
    if mutation=='symlink':
        directory=tmp_path/'source';directory.mkdir();(tmp_path/'marker').write_bytes(b'synthetic-ciphertext');(directory/'0.bin').symlink_to(tmp_path/'marker');(directory/'envelope.json').write_text(json.dumps(env))
        with pytest.raises((art.ProtocolError,OSError)):api.pack(directory)
    else:
        with pytest.raises(art.ProtocolError):api.unpack(json.dumps(body).encode(),out,100000,expected=expected,count=2 if mutation=='count' else 1,request_id='request',operation='response')
    assert not out.exists()


def test_demo_client_verdict_cannot_be_overridden_by_server_standin(tmp_path,monkeypatch):
    # No encryption is performed. Deliberately wrong synthetic answers must fail.
    def setup(w,plan,pub,priv,**kw):pub.mkdir(parents=True);priv.mkdir(parents=True);return {'parameters':{},'setup_seconds':0}
    monkeypatch.setattr(cli,'setup',setup);monkeypatch.setattr(cli,'encrypt',lambda *a,**k:{})
    monkeypatch.setattr(cli,'evaluate_server',lambda *a,**k:{'accepted':True,'request':999,'original_float':{'bad':1}})
    wrong = {key:999.0 for key in cli.analytics_reference(cli.default_inputs('analytics'))}
    monkeypatch.setattr(cli,'decrypt',lambda *a,**k:(wrong,{'max_nonresult_slot':0}))
    monkeypatch.setattr(cli,'folder_bytes',lambda *a:0)
    with pytest.raises(art.ProtocolError,match='numerical contract failed'):
        cli.run_demo('analytics',tmp_path/'demo',transport='file')
    report=json.loads((tmp_path/'demo/client/report.json').read_text())
    assert report['accepted'] is False
    assert all(row['accepted'] is False and row['request'] in (0,1) for row in report['runs'])
    assert all('bad' not in row['original_float'] for row in report['runs'])


def test_pack_refuses_traversal_and_stale_digest_without_reading_foreign_file(tmp_path):
    marker=tmp_path/'outside';marker.write_bytes(b'marker')
    source=tmp_path/'input';source.mkdir()
    env,_=payloads({'../outside':b'marker'})
    (source/'envelope.json').write_text(json.dumps(env))
    with pytest.raises(art.ProtocolError):api.pack(source)
    assert marker.read_bytes()==b'marker'
    env,_=payloads();(source/'envelope.json').write_text(json.dumps(env));(source/'0.bin').write_bytes(b'not-the-ciphertext')
    with pytest.raises(art.ProtocolError,match='integrity'):api.pack(source)


def test_group_byte_budget_and_envelope_overhead_refuse_without_output(tmp_path):
    folder=tmp_path/'budget';folder.mkdir();(folder/'a').write_bytes(b'ab');(folder/'b').write_bytes(b'cd')
    with pytest.raises(art.ProtocolError):art._tree(folder,3)
    env,body=payloads();out=tmp_path/'out'
    with pytest.raises(art.ProtocolError):api.unpack(json.dumps(body).encode(),out,30,expected=env,count=1)
    assert not out.exists()


def test_denied_cleanup_is_not_retried_and_preserves_published_output(tmp_path, monkeypatch):
    calls, journals = [], []
    real = art._settle

    def denied(*args):
        calls.append(1)
        raise PermissionError("simulated denial, not an observed OS rejection")

    monkeypatch.setattr(art, "_settle", denied)
    with pytest.raises(art.CleanupPending) as error:
        with art.staged_artifacts("request", request=tmp_path / "out",
                                  on_prepared=journals.append) as stage:
            complete(stage)
    assert len(calls) == 1
    assert error.value.cleanup_error_type == "PermissionError"
    assert journals[0].exists()
    assert (tmp_path / "out/marker").read_text() == "owned-request"
    monkeypatch.setattr(art, "_settle", real)
    assert art.recover_artifacts(journals[0])["state"] == "committed"
