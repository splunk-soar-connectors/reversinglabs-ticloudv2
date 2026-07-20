# Copyright (c) ReversingLabs, 2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

from reversinglabs_ticloudv2_views import _sanitize_download_urls


def test_sanitize_download_urls_allows_only_absolute_http_urls():
    report = {
        "pcap": "https://downloads.example.test/report.pcap",
        "screenshots": "http://downloads.example.test/screenshots.zip",
        "memory_strings": "javascript:alert(document.domain)",
        "dropped_files_url": "//downloads.example.test/files.zip",
        "classification": "MALICIOUS",
    }

    sanitized = _sanitize_download_urls(report)

    assert sanitized["pcap"] == report["pcap"]
    assert sanitized["screenshots"] == report["screenshots"]
    assert sanitized["memory_strings"] is None
    assert sanitized["dropped_files_url"] is None
    assert sanitized["classification"] == "MALICIOUS"
    assert report["memory_strings"] == "javascript:alert(document.domain)"
