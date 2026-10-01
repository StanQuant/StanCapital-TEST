"""src/data/replay/capture.py 單元測試 · 序列化往返 / append-only / manifest 對帳。"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from src.data.replay.capture import (
    CAPTURE_SCHEMA_VERSION,
    CaptureError,
    CaptureManifest,
    NormalizedCaptureWriter,
    RawCaptureEntry,
    RawCaptureWriter,
    _json_default,
    manifest_path_for,
    read_manifest,
    read_normalized_records,
    record_from_json_line,
    record_to_json_line,
    verify_capture,
)
from src.data.sinks import InMemoryMarketDataLifecycleSink, MarketDataLifecycleAction
from src.data.types import DataQualityFlag, InstrumentLink, RecordKind

from tests.data.test_types import T0, T1, make_record, make_ref

CT0 = datetime(2026, 7, 3, 2, 0, 0, tzinfo=UTC)


def make_entry(**overrides: object) -> RawCaptureEntry:
    values: dict[str, object] = {
        "capture_ts": CT0,
        "provider_id": "replay",
        "tenant_id": "acme",
        "channel": "quote/2330",
        "raw_payload": '{"px": 1000}',
        "transport_meta": (("transport", "websocket"),),
    }
    values.update(overrides)
    return RawCaptureEntry(**values)  # type: ignore[arg-type]


class TestSerializationRoundTrip:
    @pytest.mark.parametrize("kind", list(RecordKind))
    def test_all_kinds_round_trip(self, kind: RecordKind) -> None:
        # 回測可重現性的地基：序列化→還原必須位元組級等值
        record = make_record(kind, data_quality_flags=frozenset({DataQualityFlag.SUSPECT}))
        assert record_from_json_line(record_to_json_line(record)) == record

    def test_round_trip_with_none_optionals(self) -> None:
        record = make_record(RecordKind.TRADE, spec=None, sequence=None)
        restored = record_from_json_line(record_to_json_line(record))
        assert restored == record
        assert restored.spec is None
        assert restored.sequence is None

    def test_round_trip_with_links(self) -> None:
        ref = make_ref()
        linked = ref.build(
            asset_class=ref.asset_class,
            venue=ref.venue,
            provider_id=ref.provider_id,
            symbol=ref.symbol,
            currency=ref.currency,
            links=(InstrumentLink(link_type="adr_of", target_instrument_id="us_stock:nyse:TSM"),),
        )
        record = make_record(RecordKind.TRADE, instrument=linked)
        assert record_from_json_line(record_to_json_line(record)).instrument.links == linked.links

    def test_line_is_deterministic_and_sorted(self) -> None:
        # 鍵排序 + 無多餘空白：同一 record 永遠產生同一行(雜湊可重現)
        record = make_record(RecordKind.TRADE)
        line_a = record_to_json_line(record)
        line_b = record_to_json_line(record)
        assert line_a == line_b
        assert '"schema_version":1' in line_a

    def test_schema_version_mismatch_rejected(self) -> None:
        line = record_to_json_line(make_record(RecordKind.TRADE)).replace(
            '"schema_version":1', '"schema_version":99'
        )
        with pytest.raises(CaptureError) as exc:
            record_from_json_line(line)
        assert str(exc.value).startswith("capture schema 版本不符：檔案為 v99")

    def test_json_default_rejects_unknown_type(self) -> None:
        with pytest.raises(CaptureError) as exc:
            _json_default(object())
        assert str(exc.value) == "無法序列化的型別：object"


class TestRawCaptureEntry:
    def test_valid(self) -> None:
        assert make_entry().channel == "quote/2330"

    @pytest.mark.parametrize("field_name", ["provider_id", "tenant_id", "channel", "raw_payload"])
    def test_empty_identity_rejected(self, field_name: str) -> None:
        with pytest.raises(ValueError) as exc:
            make_entry(**{field_name: ""})
        assert str(exc.value) == f"{field_name} 不可為空字串"

    def test_naive_capture_ts_rejected(self) -> None:
        with pytest.raises(ValueError):
            make_entry(capture_ts=datetime(2026, 7, 3))

    def test_non_str_meta_value_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_entry(transport_meta=(("latency_ms", 5),))
        assert str(exc.value) == "transport_meta 值必須是 str，不可為 int"

    def test_empty_meta_key_rejected(self) -> None:
        with pytest.raises(ValueError) as exc:
            make_entry(transport_meta=(("", "x"),))
        assert str(exc.value) == "transport_meta 鍵 不可為空字串"


class TestRawCaptureWriter:
    def make_writer(self, path: Path) -> RawCaptureWriter:
        return RawCaptureWriter(
            path, provider_id="replay", tenant_id="acme", license_tag="replay-internal"
        )

    def test_write_finalize_and_verify(self, tmp_path: Path) -> None:
        path = tmp_path / "raw.jsonl"
        writer = self.make_writer(path)
        writer.append(make_entry())
        writer.append(make_entry(capture_ts=CT0.replace(minute=5)))
        manifest = writer.finalize()
        assert manifest.record_count == 2
        assert manifest.started_at == CT0
        assert manifest.ended_at == CT0.replace(minute=5)
        assert manifest.schema_version == CAPTURE_SCHEMA_VERSION
        assert verify_capture(path) == manifest  # 對帳通過

    def test_capture_lifecycle_creates_s05_ready_audit_projections(self, tmp_path: Path) -> None:
        sink = InMemoryMarketDataLifecycleSink()
        path = tmp_path / "audited.jsonl"
        writer = RawCaptureWriter(
            path,
            provider_id="replay",
            tenant_id="acme",
            license_tag="replay-internal",
            lifecycle_sink=sink,
            actor_id="capture-agent",
            trace_id="capture-trace",
        )
        writer.append(make_entry())
        manifest = writer.finalize()

        assert [event.action for event in sink.events] == [
            MarketDataLifecycleAction.CAPTURE_START,
            MarketDataLifecycleAction.CAPTURE_END,
        ]
        assert [record.action for record in sink.audit_records] == [
            "market_data.capture_start",
            "market_data.capture_end",
        ]
        start, end = sink.events
        assert start.actor_id == "capture-agent"
        assert start.result == "success"
        assert start.record_count == 0
        assert end.result == "success"
        assert sink.audit_records[1].metadata["manifest_sha256"] == manifest.content_sha256
        assert sink.audit_records[1].metadata["record_count"] == 1
        assert sink.audit_records[1].trace_id == "capture-trace"
        assert read_manifest(path) == manifest

    def test_capture_default_actor_and_empty_actor_contract(self, tmp_path: Path) -> None:
        sink = InMemoryMarketDataLifecycleSink()
        writer = RawCaptureWriter(
            tmp_path / "default-actor.jsonl",
            provider_id="replay",
            tenant_id="acme",
            license_tag="replay-internal",
            lifecycle_sink=sink,
        )
        writer.finalize()
        assert [event.actor_id for event in sink.events] == [
            "market-data-capture",
            "market-data-capture",
        ]

        with pytest.raises(ValueError) as exc:
            RawCaptureWriter(
                tmp_path / "bad-actor.jsonl",
                provider_id="replay",
                tenant_id="acme",
                license_tag="replay-internal",
                actor_id="",
            )
        assert str(exc.value) == "actor_id 不可為空字串"

    def test_existing_file_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "raw.jsonl"
        path.write_text("occupied")
        with pytest.raises(CaptureError) as exc:
            self.make_writer(path)
        assert "append-only 鐵律" in str(exc.value)

    def test_existing_manifest_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "raw.jsonl"
        manifest_path_for(path).write_text("{}")
        with pytest.raises(CaptureError) as exc:
            self.make_writer(path)
        assert "不可覆寫既有 capture session" in str(exc.value)

    def test_append_after_finalize_rejected(self, tmp_path: Path) -> None:
        writer = self.make_writer(tmp_path / "raw.jsonl")
        writer.finalize()
        with pytest.raises(CaptureError) as exc:
            writer.append(make_entry())
        assert str(exc.value).startswith("capture 已 finalize，不可再追加")

    def test_double_finalize_rejected(self, tmp_path: Path) -> None:
        writer = self.make_writer(tmp_path / "raw.jsonl")
        writer.finalize()
        with pytest.raises(CaptureError) as exc:
            writer.finalize()
        assert str(exc.value) == "capture 已 finalize，不可重複 finalize"

    def test_provider_mismatch_rejected(self, tmp_path: Path) -> None:
        writer = self.make_writer(tmp_path / "raw.jsonl")
        with pytest.raises(CaptureError) as exc:
            writer.append(make_entry(provider_id="other"))
        assert "一個 capture 只收單一來源" in str(exc.value)

    def test_tenant_mismatch_rejected(self, tmp_path: Path) -> None:
        writer = self.make_writer(tmp_path / "raw.jsonl")
        with pytest.raises(CaptureError) as exc:
            writer.append(make_entry(tenant_id="other"))
        assert "禁止跨租戶混寫" in str(exc.value)

    def test_empty_capture_manifest(self, tmp_path: Path) -> None:
        manifest = self.make_writer(tmp_path / "raw.jsonl").finalize()
        assert manifest.record_count == 0
        assert manifest.started_at is None
        assert manifest.ended_at is None


class TestNormalizedCaptureWriter:
    def test_write_read_round_trip(self, tmp_path: Path) -> None:
        path = tmp_path / "normalized.jsonl"
        writer = NormalizedCaptureWriter(
            path, provider_id="replay", tenant_id="acme", license_tag="replay-internal"
        )
        records = [make_record(RecordKind.TRADE), make_record(RecordKind.QUOTE)]
        for record in records:
            writer.append(record)
        manifest = writer.finalize()
        assert manifest.record_count == 2
        assert manifest.started_at == T0  # source_timestamp 當時間範圍
        assert read_normalized_records(path) == tuple(records)
        verify_capture(path)

    def test_tenant_mismatch_rejected(self, tmp_path: Path) -> None:
        writer = NormalizedCaptureWriter(
            tmp_path / "n.jsonl", provider_id="replay", tenant_id="acme", license_tag="lt"
        )
        with pytest.raises(CaptureError) as exc:
            writer.append(make_record(RecordKind.TRADE, tenant_id="other"))
        assert "禁止跨租戶混寫" in str(exc.value)

    def test_provider_mismatch_rejected(self, tmp_path: Path) -> None:
        writer = NormalizedCaptureWriter(
            tmp_path / "n.jsonl", provider_id="replay", tenant_id="acme", license_tag="lt"
        )
        other_ref = make_ref().build(
            asset_class=make_ref().asset_class,
            venue=make_ref().venue,
            provider_id="other",
            symbol=make_ref().symbol,
            currency=make_ref().currency,
        )
        with pytest.raises(CaptureError) as exc:
            writer.append(make_record(RecordKind.TRADE, instrument=other_ref, license_tag="lt"))
        assert "一個 capture 只收單一來源" in str(exc.value)

    def test_license_mismatch_rejected(self, tmp_path: Path) -> None:
        writer = NormalizedCaptureWriter(
            tmp_path / "n.jsonl",
            provider_id="replay",
            tenant_id="acme",
            license_tag="replay-internal",
        )
        with pytest.raises(CaptureError) as exc:
            writer.append(make_record(RecordKind.TRADE, license_tag="other-license"))
        assert "禁止授權來源標記漂移" in str(exc.value)


class TestVerification:
    def make_finalized(self, tmp_path: Path) -> Path:
        path = tmp_path / "raw.jsonl"
        writer = RawCaptureWriter(path, provider_id="replay", tenant_id="acme", license_tag="lt")
        writer.append(make_entry())
        writer.finalize()
        return path

    def test_tampered_content_detected(self, tmp_path: Path) -> None:
        path = self.make_finalized(tmp_path)
        content = path.read_text()
        tampered = content.replace("websocket", "tampered0")
        assert tampered != content  # 防呆：確定真的改到內容
        path.write_text(tampered)
        with pytest.raises(CaptureError) as exc:
            verify_capture(path)
        assert "capture 內容雜湊不符" in str(exc.value)

    def test_count_mismatch_detected(self, tmp_path: Path) -> None:
        path = self.make_finalized(tmp_path)
        manifest_path = manifest_path_for(path)
        tampered = manifest_path.read_text().replace('"record_count": 1', '"record_count": 5')
        manifest_path.write_text(tampered)
        # 內容雜湊仍相符(改的是 manifest)，記錄數不符要被抓到
        with pytest.raises(CaptureError) as exc:
            verify_capture(path)
        assert "capture 記錄數不符" in str(exc.value)

    def test_blank_line_is_not_counted_as_record(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.jsonl"
        manifest = RawCaptureWriter(
            path, provider_id="replay", tenant_id="acme", license_tag="lt"
        ).finalize()
        path.write_bytes(b"\n")
        manifest_path = manifest_path_for(path)
        manifest_path.write_text(
            manifest_path.read_text().replace(
                manifest.content_sha256, hashlib.sha256(b"\n").hexdigest()
            )
        )
        assert verify_capture(path).record_count == 0

    def test_missing_manifest_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "raw.jsonl"
        path.write_text("")
        with pytest.raises(CaptureError) as exc:
            verify_capture(path)
        assert "無對帳單的 capture 不可信" in str(exc.value)

    def test_missing_capture_rejected_after_manifest_read(self, tmp_path: Path) -> None:
        path = self.make_finalized(tmp_path)
        path.unlink()
        with pytest.raises(CaptureError) as exc:
            verify_capture(path)
        assert str(exc.value).startswith(f"無法讀取 capture：{path}")

    @pytest.mark.parametrize("manifest_text", ["{", "{}"])
    def test_invalid_manifest_rejected(self, tmp_path: Path, manifest_text: str) -> None:
        path = tmp_path / "raw.jsonl"
        path.write_text("")
        manifest_path_for(path).write_text(manifest_text)
        with pytest.raises(CaptureError) as exc:
            verify_capture(path)
        assert str(exc.value).startswith(f"manifest 格式無效：{manifest_path_for(path)}")


class TestCaptureManifest:
    def test_validation(self) -> None:
        with pytest.raises(ValueError):
            CaptureManifest(
                schema_version=1,
                provider_id="",
                tenant_id="acme",
                license_tag="lt",
                record_count=0,
                started_at=None,
                ended_at=None,
                content_sha256="0" * 64,
            )
        with pytest.raises(ValueError):
            CaptureManifest(
                schema_version=1,
                provider_id="replay",
                tenant_id="acme",
                license_tag="lt",
                record_count=-1,
                started_at=None,
                ended_at=None,
                content_sha256="0" * 64,
            )
        with pytest.raises(ValueError):
            CaptureManifest(
                schema_version=1,
                provider_id="replay",
                tenant_id="acme",
                license_tag="lt",
                record_count=0,
                started_at=datetime(2026, 7, 3),  # naive
                ended_at=None,
                content_sha256="0" * 64,
            )
        with pytest.raises(ValueError):
            CaptureManifest(
                schema_version=1,
                provider_id="replay",
                tenant_id="acme",
                license_tag="lt",
                record_count=0,
                started_at=None,
                ended_at=datetime(2026, 7, 3),  # naive
                content_sha256="0" * 64,
            )

    @pytest.mark.parametrize("schema_version", [True, "1", 2])
    def test_schema_version_rejected(self, schema_version: object) -> None:
        with pytest.raises(ValueError):
            CaptureManifest(
                schema_version=schema_version,  # type: ignore[arg-type]
                provider_id="replay",
                tenant_id="acme",
                license_tag="lt",
                record_count=0,
                started_at=None,
                ended_at=None,
                content_sha256="0" * 64,
            )

    @pytest.mark.parametrize("content_sha256", ["abc", "G" * 64, "A" * 64, "X" * 64])
    def test_sha256_format_rejected(self, content_sha256: str) -> None:
        with pytest.raises(ValueError) as exc:
            CaptureManifest(
                schema_version=1,
                provider_id="replay",
                tenant_id="acme",
                license_tag="lt",
                record_count=0,
                started_at=None,
                ended_at=None,
                content_sha256=content_sha256,
            )
        assert str(exc.value) == "content_sha256 必須是 64 碼小寫十六進位 SHA-256"

    @pytest.mark.parametrize(
        ("record_count", "started_at", "ended_at", "message"),
        [
            (0, CT0, CT0, "空 capture 的 started_at / ended_at 必須為 None"),
            (1, None, None, "非空 capture 必須有 started_at / ended_at"),
            (1, CT0, None, "started_at 與 ended_at 必須同時存在或同時為 None"),
            (1, None, CT0, "started_at 與 ended_at 必須同時存在或同時為 None"),
            (1, CT0.replace(minute=1), CT0, "started_at 不可晚於 ended_at"),
        ],
    )
    def test_time_count_consistency_rejected(
        self,
        record_count: int,
        started_at: datetime | None,
        ended_at: datetime | None,
        message: str,
    ) -> None:
        with pytest.raises(ValueError) as exc:
            CaptureManifest(
                schema_version=1,
                provider_id="replay",
                tenant_id="acme",
                license_tag="lt",
                record_count=record_count,
                started_at=started_at,
                ended_at=ended_at,
                content_sha256="0" * 64,
            )
        assert str(exc.value) == message

    def test_time_range_uses_min_max_of_out_of_order_entries(self, tmp_path: Path) -> None:
        # capture_ts 亂序寫入時，manifest 時間範圍仍是 min/max
        writer = RawCaptureWriter(
            tmp_path / "raw.jsonl", provider_id="replay", tenant_id="acme", license_tag="lt"
        )
        late = CT0.replace(minute=30)
        writer.append(make_entry(capture_ts=late))
        writer.append(make_entry(capture_ts=CT0))  # 較早的後寫
        manifest = writer.finalize()
        assert manifest.started_at == CT0
        assert manifest.ended_at == late

    def test_t1_is_after_t0(self) -> None:
        assert T1 > T0  # fixture 前提防呆
