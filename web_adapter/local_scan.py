"""Stream local text, gzip and tar archives without extracting datasets to disk."""

import gzip
from multiprocessing import Pool
import os
import tarfile

from h8mail.utils.classes import local_breach_target

MAX_LINE_BYTES = 256 * 1024
MAX_RESULTS = 5000
MAX_CAPTURED_BYTES = 2 * 1024 * 1024
MAX_WORKERS = 4


class LocalScanError(Exception):
    """Fail the entire scan when a source is unreadable or bounded output is exceeded."""


def _result_size(match: local_breach_target) -> int:
    return len(match.content.encode("utf-8")) + len(match.filepath.encode("utf-8")) + len(match.target.encode("utf-8"))


def _append_matches(matches: list, incoming: list, captured_bytes: int) -> int:
    if len(matches) + len(incoming) > MAX_RESULTS:
        raise LocalScanError("The local scan exceeded 5000 matches. Narrow the search or use the CLI.")
    captured_bytes += sum(_result_size(match) for match in incoming)
    if captured_bytes > MAX_CAPTURED_BYTES:
        raise LocalScanError("The local scan exceeded the safe result size. Narrow the search or use the CLI.")
    matches.extend(incoming)
    return captured_bytes


def _scan_stream(stream, filepath: str, targets: tuple[str, ...], matches: list, captured_bytes: int) -> int:
    line_number = 0
    while True:
        line = stream.readline(MAX_LINE_BYTES + 1)
        if not line:
            return captured_bytes
        if len(line) > MAX_LINE_BYTES:
            raise LocalScanError("A local source contains a line larger than 256 KiB. Use the CLI for this file.")
        decoded = line.decode("cp437")
        incoming = [local_breach_target(target, filepath, line_number, decoded)
                    for target in targets if target in decoded]
        captured_bytes = _append_matches(matches, incoming, captured_bytes)
        line_number += 1


def _is_tar_header(header: bytes) -> bool:
    if len(header) != 512:
        return False
    if not header.strip(b"\x00"):
        return True
    try:
        tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
    except tarfile.HeaderError:
        return False
    return True


def _scan_file(filepath: str, targets: tuple[str, ...], gzip_mode: bool) -> list:
    matches = []
    captured_bytes = 0
    try:
        with (gzip.open(filepath, "rb") if gzip_mode else open(filepath, "rb")) as stream:
            if gzip_mode:
                header = stream.read(512)
                stream.seek(0)
            else:
                header = b""
            if gzip_mode and _is_tar_header(header):
                with tarfile.open(fileobj=stream, mode="r|") as archive:
                    for member in archive:
                        if not member.isfile():
                            continue
                        if len(member.name) > 2048:
                            raise LocalScanError("An archive member name exceeds the safe length limit.")
                        member_stream = archive.extractfile(member)
                        if member_stream is None:
                            raise LocalScanError("An archive member could not be read.")
                        with member_stream:
                            captured_bytes = _scan_stream(
                                member_stream, filepath + "!" + member.name, targets, matches, captured_bytes,
                            )
            else:
                _scan_stream(stream, filepath, targets, matches, captured_bytes)
        return matches
    except LocalScanError:
        raise
    except (OSError, EOFError, tarfile.TarError, ValueError):
        raise LocalScanError("A selected local source could not be read. Check its format and permissions.") from None


def _scan_job(arguments: tuple[str, tuple[str, ...], bool]) -> list:
    return _scan_file(*arguments)


def scan_files(files, targets, gzip_mode: bool = False, single_file: bool = False) -> list:
    """Return original engine match objects, with identical literal substring matching.

    Any failed source or exceeded bound fails the search; incomplete input never
    becomes a confirmed empty result. Tar members remain in their compressed stream.
    """
    if type(gzip_mode) is not bool or type(single_file) is not bool:
        raise LocalScanError("Invalid local scan mode.")
    target_patterns = tuple(dict.fromkeys(targets))
    if any(not isinstance(target, str) or not target for target in target_patterns):
        raise LocalScanError("Local target patterns must be nonempty strings.")
    if not target_patterns:
        return []
    file_iterator = iter(dict.fromkeys(os.fspath(filepath) for filepath in files))
    matches = []
    captured_bytes = 0
    if single_file:
        for filepath in file_iterator:
            captured_bytes = _append_matches(matches, _scan_file(filepath, target_patterns, gzip_mode), captured_bytes)
        return matches
    # Pool termination is public on Python 3.12 and immediately stops sibling scans
    # when one source fails. Executor.shutdown() would wait for large running files.
    with Pool(processes=MAX_WORKERS) as pool:
        try:
            jobs = ((filepath, target_patterns, gzip_mode) for filepath in file_iterator)
            for found in pool.imap_unordered(_scan_job, jobs, chunksize=1):
                if not isinstance(found, list):
                    raise LocalScanError("A local scan worker could not complete its source.")
                captured_bytes = _append_matches(matches, found, captured_bytes)
        except Exception as exc:
            pool.terminate()
            if isinstance(exc, LocalScanError):
                raise
            raise LocalScanError("A local scan worker could not complete its source.") from None
    return matches
