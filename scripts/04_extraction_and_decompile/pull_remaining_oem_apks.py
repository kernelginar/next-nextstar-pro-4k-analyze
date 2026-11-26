"""Pull and decompile remaining non-Google OEM APKs and updated /oem app for completeness."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pull_and_decompile import pull_and_decompile_targets

if __name__ == "__main__":
    remaining_targets: list[tuple[str, str, bool]] = [
        ("/system/app/SdtFrontPanelLedsService/SdtFrontPanelLedsService.apk", "system_apps", True),
        ("/system/app/SdtGtvPartnerConfig/SdtGtvPartnerConfig.apk", "system_apps", True),
        ("/system/app/RtkPartnerInterface/RtkPartnerInterface.apk", "system_apps", True),
        ("/data/app/~~Dyjuf2qzCSjqPwiHWuQE0A==/com.jettv.player-hrjEoLct64GV_l0V0YXVzg==/base.apk", "data_apps", True),
    ]
    pull_and_decompile_targets(remaining_targets)
