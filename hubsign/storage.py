"""Document storage: local directory or any S3-compatible bucket."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .config import Settings


class LocalStorage:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    def put(self, key: str, data: bytes) -> None:
        p = self.root / key
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(p)  # atomic: readers never see a half-written file

    def get(self, key: str) -> bytes | None:
        p = self.root / key
        return p.read_bytes() if p.exists() else None

    def delete(self, key: str) -> None:
        (self.root / key).unlink(missing_ok=True)

    def ping(self) -> None:
        self.root.stat()


class DbStorage:
    """Documents as rows in the database. No disk and no bucket to run, so it works on hosts with neither (a free
    web service plus a free Postgres). A PDF is typically 50-500 KB, so a 0.5 GB database holds thousands."""

    def __init__(self, db):
        self.db = db

    def put(self, key: str, data: bytes) -> None:
        self.db.x(
            "INSERT INTO blobs(k,data,created_at) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET data=excluded.data",
            (key, data, datetime.now(UTC).isoformat(timespec="seconds")),
        )

    def get(self, key: str) -> bytes | None:
        r = self.db.one("SELECT data FROM blobs WHERE k=?", (key,))
        return bytes(r["data"]) if r else None

    def delete(self, key: str) -> None:
        self.db.x("DELETE FROM blobs WHERE k=?", (key,))

    def ping(self) -> None:
        self.db.q("SELECT 1 AS ok")


class S3Storage:
    def __init__(self, s: Settings):
        import boto3

        self.bucket, self.prefix = s.s3_bucket, s.s3_prefix.strip("/")
        self.c = boto3.client("s3", endpoint_url=s.s3_endpoint_url or None, region_name=s.s3_region or None)

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, key: str, data: bytes) -> None:
        self.c.put_object(
            Bucket=self.bucket,
            Key=self._k(key),
            Body=data,
            ContentType="application/pdf",
            ServerSideEncryption="AES256",
        )

    def get(self, key: str) -> bytes | None:
        try:
            return self.c.get_object(Bucket=self.bucket, Key=self._k(key))["Body"].read()
        except self.c.exceptions.NoSuchKey:
            return None

    def delete(self, key: str) -> None:
        self.c.delete_object(Bucket=self.bucket, Key=self._k(key))

    def ping(self) -> None:
        self.c.head_bucket(Bucket=self.bucket)


def make_storage(s: Settings, db=None):
    if s.s3_bucket:
        return S3Storage(s)
    if s.documents_in_database and db is not None:
        return DbStorage(db)
    return LocalStorage(s.data_dir / "docs")
