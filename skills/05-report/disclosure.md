# Skill 05-C: Responsible Disclosure

## 목적
취약점을 발견한 프로젝트 메인테이너에게 책임감 있게 제보하기 위한
이메일 초안과 GitHub Security Advisory 초안을 작성한다.

## 제보 전 체크리스트
- [ ] CVSS ≥ 4.0 (MEDIUM 이상) 취약점만 제보
- [ ] 신뢰도 ≥ 0.35 이상
- [ ] 저장소의 SECURITY.md 또는 security 연락처 확인
- [ ] 보고서 작성 완료 (05-A)

## SECURITY.md 확인
```bash
find <local_path> -name "SECURITY.md" -o -name "SECURITY.txt" | head -5
cat <local_path>/SECURITY.md
```

## 이메일 초안 템플릿

파일: `reports/<repo-name>/DISCLOSURE_EMAIL.md`

```markdown
Subject: [Security] <취약점 유형> Vulnerability in <프로젝트명> (<파일경로>)

Hello <프로젝트명> Security Team,

I am a security researcher and have discovered a <심각도> severity
<취약점 유형> vulnerability in <프로젝트명>.

**Summary**
<한 줄 요약>

**Severity**: CVSS 3.1 <점수> (<심각도>)
**Affected File**: `<파일경로>` (line <라인>)

**Description**
<3-5문장 설명>

**Impact**
<실제 공격 시나리오와 피해>

**Remediation**
<권장 수정 방법>

I am happy to provide a full technical report and work with you
on a coordinated disclosure timeline.

Please acknowledge receipt of this report within 7 days.
I will keep this information confidential for 90 days from this date
to allow time for a fix to be released.

Regards,
<이름>
```

## GitHub Security Advisory 초안 템플릿

파일: `reports/<repo-name>/GITHUB_ADVISORY.md`

```markdown
# GitHub Security Advisory Draft

## Ecosystem
<npm | PyPI | Go | Maven>

## Package Name
<패키지 이름>

## Affected Versions
< <버전 (분석 당시 최신)>

## Patched Version
N/A (미패치)

## Severity
<CRITICAL | HIGH | MEDIUM | LOW>

## CVSS Vector
`CVSS:3.1/<벡터>`

## Description
<취약점 설명>

## Patch
<권장 수정 방법>

## References
- <보고서 URL 또는 PoC>
```

## 제보 후 타임라인 기록

제보 후 아래 날짜를 기록한다.
- **제보일**: <날짜>
- **응답 기한**: 제보일 + 7일
- **공개 기한**: 제보일 + 90일 (업계 표준)
- **패치 확인일**: (추후 기입)
