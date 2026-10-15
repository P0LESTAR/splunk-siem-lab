# SPL 문법 정리

> Splunk SIEM 홈랩 실습(SMB Brute Force 탐지)에서 사용한 쿼리를 기준으로 정리한 SPL 기초 문법.
> 데이터: `index=wineventlog` (XmlWinEventLog, win-vic)

---

## 0. 기본 구조: 파이프라인

```
검색 조건 | 명령1 | 명령2 | 명령3
```

- `|` 왼쪽의 결과가 오른쪽 명령의 입력으로 들어간다. 리눅스의 `cat log | grep | sort | uniq -c`와 같은 방식이다.
- **왼쪽에서 오른쪽으로, 한 줄씩** 읽으면 된다.

거의 모든 쿼리가 아래 4단계 흐름을 따른다.

| 단계 | 하는 일 | 대표 명령 |
|---|---|---|
| ① 가져오기 | 어떤 로그를 볼지 정함 | (첫 줄, 파이프 앞) |
| ② 가공 | 필드를 만들거나 바꿈 | `eval`, `rex`, `rename` |
| ③ 집계 | 묶어서 숫자를 냄 | `stats`, `timechart` |
| ④ 정리 | 거르기, 정렬, 보기 좋게 다듬기 | `where`, `sort`, `table`, `convert` |

---

## 1. 첫 줄(파이프 앞) = 검색 조건

```spl
index=wineventlog EventCode=4625 IpAddress=10.10.10.100
```

| 문법 | 의미 | 예 |
|---|---|---|
| `필드=값` | 이 값을 가진 이벤트만 가져옴 | `EventCode=4625` |
| 공백 | **AND** (생략된 것) | `A B` = `A AND B` |
| `OR` | 둘 중 하나 (**대문자 필수**) | `(EventCode=4625 OR EventCode=4624)` |
| `NOT` / `!=` | 제외 | `IpAddress!="-"` |
| `*` | 와일드카드 | `TargetUserName=admin*` |
| `"..."` | 공백이 들어간 값 | `TargetUserName="ANONYMOUS LOGON"` |
| `IN` | OR의 축약형 | `EventCode IN (4624, 4625, 4740)` |

- **`index=`는 항상 맨 앞에 쓴다.** 빼면 모든 인덱스를 다 뒤져서 느려진다. 실무에서 가장 기본적인 성능 습관이다.
- **`!=`와 `NOT`의 차이**
  - `IpAddress!="-"`: IpAddress 필드가 **있고**, 값이 `-`가 아닌 이벤트만 가져온다.
  - `NOT IpAddress="-"`: 위 결과에 더해 IpAddress 필드가 **아예 없는** 이벤트까지 가져온다. 4740 같은 이벤트가 여기에 해당한다.

---

## 2. `stats`: 가장 중요한 명령

`stats`는 SQL의 `GROUP BY`와 같다. 탐지 룰의 대부분이 `stats`로 만들어진다.

```spl
| stats 함수(필드) as 새이름  함수(필드) as 새이름 ...  by 묶을필드1 묶을필드2
```

예제:

```spl
| stats count as failure_count  dc(TargetUserName) as unique_users  by IpAddress
```

→ **IpAddress별로** 이벤트 개수와 서로 다른 계정 수를 계산한다.

| 함수 | 의미 | 블루팀에서 쓰는 곳 |
|---|---|---|
| `count` | 이벤트 개수 | 실패 횟수 |
| `dc(필드)` | 값의 종류 개수 (distinct count) | 몇 개 계정을 노렸는지 → Spraying 판별 |
| `values(필드)` | 값 목록 (중복 제거) | 노린 계정 이름 목록 |
| `min(필드)` / `max(필드)` | 최소 / 최대 | `min(_time)` = 처음 본 시각 |
| `sum`, `avg` | 합계, 평균 | 전송 바이트 합계 등 |
| `latest(필드)` | 가장 최근 값 | 마지막 로그인 IP |

### ⚠️ stats의 함정 2가지

**① `stats` 다음에는 stats가 만든 필드만 남는다.**

```spl
| stats count by IpAddress
| table IpAddress TargetUserName    ← TargetUserName은 비어 있음
```

stats를 지나면 원본 이벤트는 사라지고 집계표만 남는다. 나중에 쓸 필드는 stats 안에서 `values()` 등으로 같이 뽑아둬야 한다.

**② `by` 필드가 없는 이벤트는 결과에서 빠진다.**

- 4740(계정 잠금) 이벤트에는 `IpAddress`가 없다.
- 그래서 `by IpAddress`로 묶으면 4740은 결과에서 **조용히 사라진다.** 오류도 나지 않는다.
- 4625와 4740을 함께 보려면 IP가 아니라 **계정(`TargetUserName`) 기준**으로 묶어야 한다.

---

## 3. `eval`: 필드 만들기/계산하기

```spl
| eval 새필드 = 식
```

```spl
| eval user = lower(TargetUserName)
| eval attack_type = if(unique_users>=5, "Password Spraying", "Brute Force")
| eval duration_min = round((last_seen - first_seen)/60, 1)
```

| 함수 | 의미 |
|---|---|
| `if(조건, 참일때, 거짓일때)` | 조건 분기 |
| `case(조건1,값1, 조건2,값2, true(),기본값)` | 여러 갈래 분기 (switch문) |
| `lower()` / `upper()` | 대소문자 변환 |
| `null()` | 빈 값 |
| `round(x, 자릿수)` | 반올림 |
| `strftime(_time, "%Y-%m-%d %H:%M")` | 시간을 사람이 읽는 형식으로 바꿈 |
| `len()`, `substr()`, `replace()` | 문자열 처리 |

### eval 안에서 헷갈리는 기호

| 쓰는 법 | 의미 |
|---|---|
| `==` | 같은지 비교 (`=`도 동작하지만 `==`가 명확함) |
| `"administrator"` | **문자열** 값 |
| `'Account Name'` | **필드 이름** (공백이 들어간 필드명에 씀) |
| `AND` `OR` `NOT` | 논리 연산 |

### 대소문자 규칙: `lower()`를 쓰는 이유

| 위치 | 대소문자 구분 |
|---|---|
| 첫 줄 검색 **값** | ❌ 구분 안 함 (`administrator` = `Administrator`) |
| **필드 이름** | ✅ 구분함 (`IpAddress` ≠ `ipaddress`) |
| `eval` / `where` / `stats by`의 **값** | ✅ 구분함 |

`stats by TargetUserName`을 하면 공격자가 입력한 `administrator`와 실제 계정 `Administrator`가 다른 행으로 나뉜다. `lower()`로 소문자로 통일한 다음 묶어야 한다.

---

## 4. 자주 보이는 패턴: `count(eval(...))`

```spl
| stats count(eval(EventCode==4625)) as fail
        count(eval(EventCode==4624)) as success
        by IpAddress
```

뜻은 **"조건이 참인 이벤트만 센다"**이다. 엑셀의 `COUNTIF`와 같다. 이 방식을 쓰면 실패 수와 성공 수를 **한 번의 stats로** 나란히 뽑을 수 있다.

- `eval()` 안의 조건이 참이면 값이 생기고, 거짓이면 null이 된다.
- `count`는 null을 세지 않으므로 결과적으로 조건에 맞는 것만 세게 된다.

같은 원리로 아래 패턴도 자주 쓴다.

```spl
| eval fail_time=if(EventCode==4625, _time, null())
| stats min(fail_time) as first_fail
```

→ "실패 이벤트의 시각 중 가장 이른 것"을 구한다.

---

## 5. 나머지 자주 쓰는 명령

| 명령 | 의미 | 예 |
|---|---|---|
| `where` | 계산된 결과로 거르기 | `where failure_count >= 20` |
| `search` | 파이프 중간에서 단순 검색 | `search user="admin*"` |
| `table` | 보여줄 열만 골라서 표로 출력 | `table _time host user` |
| `sort` | 정렬 (`-`는 내림차순) | `sort - failure_count` |
| `head N` | 상위 N개 | `head 10` |
| `rename` | 필드 이름 바꾸기 | `rename IpAddress as src_ip` |
| `dedup` | 중복 제거 | `dedup IpAddress` |
| `top` / `rare` | 가장 많은 값 / 가장 드문 값 | `top limit=10 IpAddress` |
| `timechart` | 시간대별 그래프 | `timechart span=1m count by IpAddress` |
| `convert ctime()` | epoch 숫자를 날짜로 변환 | `convert ctime(first_seen)` |
| `rex` | 정규식으로 필드 추출 | `rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"` |

### `where`와 `search`의 차이

- **`stats`나 `eval`로 만든 숫자를 비교할 때는 `where`**를 쓴다. `search failure_count>=20`도 동작은 하지만, 숫자/문자 비교가 애매하게 처리될 수 있다.
- `where`는 eval과 같은 문법이다. 그래서 `where user!="anonymous logon"`처럼 문자열에 **따옴표가 필요**하고, **대소문자도 구분**한다.

### `_time`에 대해

- `_time`은 내부적으로 **epoch 초(숫자)**로 저장된다. 화면에 날짜로 보이는 건 Splunk가 표시할 때만 바꿔주기 때문이다.
- 그래서 `stats min(_time)`을 하면 숫자가 나오고, `convert ctime()`으로 다시 날짜로 바꿔야 한다.
- 숫자이기 때문에 `last_success > first_fail`처럼 **시간 순서를 비교할 수 있다.**

---

## 6. 실전: 탐지 룰 한 줄씩 읽기

**탐지 룰: Brute Force 후 로그인 성공 (Critical)**

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624) IpAddress!="-" IpAddress!="127.0.0.1"
| eval user=lower(TargetUserName)
| where user!="anonymous logon"
| eval fail_time=if(EventCode==4625,_time,null()), ok_time=if(EventCode==4624,_time,null())
| stats count(eval(EventCode==4625)) as fail
        count(eval(EventCode==4624)) as success
        min(fail_time) as first_fail max(ok_time) as last_success
        by host IpAddress user
| where fail>=10 AND success>0 AND last_success>first_fail
| convert ctime(first_fail) ctime(last_success)
```

| 줄 | 코드 | 의미 |
|---|---|---|
| ① | `index=wineventlog (EventCode=4625 OR EventCode=4624) IpAddress!="-" IpAddress!="127.0.0.1"` | 로그인 실패/성공 이벤트 중, 네트워크 출발지가 있는 것만 가져온다. |
| ② | `eval user=lower(TargetUserName)` | 계정명을 소문자로 통일한다. `Administrator`와 `administrator`를 같은 계정으로 보기 위해서다. |
| ③ | `where user!="anonymous logon"` | 익명 로그인(SMB Null Session)을 제외한다. 정찰 흔적이지 침해가 아니라서 오탐이 된다. |
| ④ | `eval fail_time=..., ok_time=...` | 실패 이벤트에는 `fail_time`, 성공 이벤트에는 `ok_time`에 시각을 넣는다. 쉼표로 eval 여러 개를 한 줄에 쓸 수 있다. |
| ⑤ | `stats ... by host IpAddress user` | **대상 서버 + 공격자 IP + 계정** 조합별로 실패 수, 성공 수, 첫 실패 시각, 마지막 성공 시각을 계산한다. |
| ⑥ | `where fail>=10 AND success>0 AND last_success>first_fail` | "10번 넘게 실패했고, **그 뒤에** 성공했다"는 조건에 맞는 행만 남긴다. 경고가 울리는 조건이다. |
| ⑦ | `convert ctime(first_fail) ctime(last_success)` | 시각을 사람이 읽을 수 있는 형식으로 바꾼다. |
