# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Agent Catalog — discovery-plane persistence and public serialization.

The catalog is a read-optimised index of discoverable commerce agents.
It does NOT hold authoritative identity, runtime state, or private
merchant metadata.  See docs/shopping-cli-a2a-upgrade-design-v1.2.1.md.
"""

from __future__ import annotations
