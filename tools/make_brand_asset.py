"""Generate the original CloverKit vector/raster mark; no photographs or metadata."""
# SPDX-License-Identifier: GPL-2.0-or-later
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def generate():
 from PIL import Image,ImageDraw
 size=1200;image=Image.new('RGB',(size,size),(8,17,13));draw=ImageDraw.Draw(image)
 leaves=[((310,225,655,640),(34,115,66)),((545,225,890,640),(43,133,75)),((310,500,655,915),(29,99,59)),((545,500,890,915),(38,122,68))]
 svg=['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 1200"><rect width="1200" height="1200" fill="#08110d"/>']
 for (x1,y1,x2,y2),colour in leaves:
  draw.ellipse((x1,y1,x2,y2),fill=colour);svg.append(f'<ellipse cx="{(x1+x2)/2}" cy="{(y1+y2)/2}" rx="{(x2-x1)/2}" ry="{(y2-y1)/2}" fill="rgb{colour}"/>')
 draw.line([(600,560),(610,875),(550,1050)],fill=(51,137,77),width=22)
 svg.append('<path d="M600 560 L610 875 L550 1050" fill="none" stroke="#33894d" stroke-width="22"/></svg>')
 (ROOT/'assets/clover.svg').write_text(''.join(svg)+'\n')
 image.save(ROOT/'src/panel/clover-boot.png',optimize=True)
if __name__=='__main__':generate()
