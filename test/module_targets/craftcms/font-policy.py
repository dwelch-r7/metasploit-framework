from pathlib import Path
# ImageMagick 7.1.1-32 RenderType reads the supported system:font policy.
path = Path('/etc/ImageMagick-7/policy.xml')
data = path.read_text()
assert data.count('</policymap>') == 1
entry = '<policy domain="system" name="font" value="/usr/share/fonts/dejavu/DejaVuSans.ttf"/>'
assert entry not in data
path.write_text(data.replace('</policymap>', entry + '\n</policymap>'))
