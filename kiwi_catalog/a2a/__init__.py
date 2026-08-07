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

"""Hosted A2A publication — Agent Card and UCP Profile generation (v2.4-W1).

A read-only projection layer that derives protocol documents from existing
catalog / merchant state without introducing any write semantics.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §14, §18
Binding: docs/a2a/shopping-cli-a2a-binding-1.0-rc1.md §5–§6
"""

from kiwi_catalog.a2a.agent_card import build_hosted_agent_card
from kiwi_catalog.a2a.ucp_profile import build_hosted_ucp_profile

__all__ = ["build_hosted_agent_card", "build_hosted_ucp_profile"]
