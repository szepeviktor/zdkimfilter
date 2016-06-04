#! /usr/bin/env python
"""
Build database tables diagram (svg and html)

Usage:
	dbgraph.py [options]  [--pod=<in>]... --sql=<in>

Options:
--help                show this
--image-map           use image map, not css
--dpi=<dotsperinch>   inkscape export [default: 18.0]
--out=<dir/base>      output name for svg/html  [default: ./fig_final]
--out-html=<fullname> override output name for html
--pod=<perl.pod>      pod files with '=item <field>X<table>' marks
--svg=<template.svg>  template to add on top of drawing
--txt=<boilerplate>   html template with a "<!-- dbgraph -->" mark
"""

# see http://neuroscience.telenczuk.pl/?p=331
import svgutils.transform as sg
import sys
import os.path 
import re
from docopt import docopt
import subprocess
import cgi


# 500.1907

# don't expect the rest to magically fit...
RECT_HEIGHT = 78.20122
RECT_WIDTH = 567.9824
LEFT_MARGIN = 32.6354
BASELINE_DISP = 59.13325

FIG_WIDTH = 2427.88
FIG_HEIGHT = 2637.59

DOTS_PER_INCH = 90.0

# upper left coordinate for each table
table_coord = {
	'domain': (73.22, 140.46),
	'msg_ref': (930, 140.46),
	'message_in': (1784.75, 140.46),
	'user': (73.22, 1619.36),
	'message_out': (930, 1479.35),
	'msg_out_ref': (930, 1043.59)}

# table/field links: dictionary of
#     table['-'field]: {'coord': (x, y), 'def': blah, 'descr': blah}
image_map = {}

# generic intro
class intro: pass
intro.track = False
intro.para = ''

# background element
background = sg.fromstring('''<?xml version="1.0" encoding="UTF-8" ?>
<svg>
  <path
     style="color:#000000;fill:#ffeeaa;fill-opacity:1;fill-rule:nonzero;stroke:#003000;stroke-width:7.92078352;stroke-linecap:butt;stroke-linejoin:miter;stroke-miterlimit:4;stroke-dashoffset:0;stroke-opacity:1;marker:none;visibility:visible;display:inline;overflow:visible;enable-background:accumulate"
     d="m 63.739544,3.9653885 2300.419856,0 c 33.1097,0 59.7648,26.6551095 59.7648,59.7648205 l 0,2510.122491 c 0,33.1097 -26.6551,59.7648 -59.7648,59.7648 l -2300.419856,0 c -33.10971,0 -59.7648202,-26.6551 -59.7648202,-59.7648 l 0,-2510.122491 c 0,-33.109711 26.6551102,-59.7648205 59.7648202,-59.7648205 z"/>
</svg>
''')

class RectElement(sg.FigureElement):
    '''inkscape rectangle using style
       x, y = upper left corner of the element
    '''
    def __init__(self, x, y, is_index):
        fill = 'a6a607' if is_index else 'ffcc66'
        style = 'fill:#' + fill + ';fill-opacity:1;stroke:#003000;stroke-width:4;stroke-linecap:butt;stroke-linejoin:miter;stroke-miterlimit:4;stroke-opacity:1;stroke-dasharray:none'
        linedata = "m %.5f,%.5f 0,%.5f %.5f,0 0,%.5f z" % (x, y, RECT_HEIGHT, RECT_WIDTH, -RECT_HEIGHT)
        line = sg.etree.Element(sg.SVG+"path", 
                {"d": linedata, 
                 "style": style}) 
        sg.FigureElement.__init__(self, line)

class TextElement(sg.FigureElement):
    '''inkscape text using style.'''
    def __init__(self, x, y, text, title=False):
        stylefmt='font-size:56px;font-style:normal;font-variant:normal;font-weight:%s;font-stretch:normal;text-align:start;line-height:100%%;letter-spacing:0px;word-spacing:0px;writing-mode:lr-tb;text-anchor:%s;fill:#000000;fill-opacity:1;stroke:none;font-family:Arial'
        if title:
           style = stylefmt % ('bold', 'middle')
           x += RECT_WIDTH/2.0
        else:
           style = stylefmt % ('normal', 'start')
           x += LEFT_MARGIN
        y += BASELINE_DISP

        txt = sg.etree.Element(sg.SVG+"text", 
                {"x": str(x), "y": str(y),
                 "style": style})
        txt.text = text
        sg.FigureElement.__init__(self, txt)

def add_field(x, y, f, table_name):
	'''draw a rectangle with field name, return group'''
	name = f[0]
	x_shift = 63.150 if table_name == 'message_in' and name == 'id' else 0
	txt = TextElement(x + x_shift, y, name)
	green_key = (table_name.startswith('message_') and name in {'ino', 'mtime', 'pid'} or
		table_name == name and name == 'domain')
	rect = RectElement(x, y, green_key)
	image_map[table_name + '-' + name] = {'coord': (x, y), 'def': f[1], 'descr': ''}
	return sg.GroupElement([rect, txt])


class TabletopElement(sg.FigureElement):
    '''inkscape half rounded rectangle using style
       x, y: upper left corner of the element
    '''
    def __init__(self, x, y, style='color:#000000;fill:#a60507;fill-opacity:1;fill-rule:nonzero;stroke:#003000;stroke-width:4;stroke-linecap:butt;stroke-linejoin:miter;stroke-miterlimit:4;stroke-opacity:1;stroke-dashoffset:0;marker:none;visibility:visible;display:inline;overflow:visible;enable-background:accumulate'):
        # 499.66872 was 293.92875
        linedata = "m %.5f,%.5f 0,-43.94757 c 0,-18.9229 15.23396,-34.15685 34.15685,-34.15685 l 499.66872,0 c 18.9229,0 34.15685,15.23395 34.15685,34.15685 l 0,43.94757 z" % (x, y + RECT_HEIGHT)
        line = sg.etree.Element(sg.SVG+"path", 
                {"d": linedata, 
                 "style": style}) 
        sg.FigureElement.__init__(self, line)

def add_table(fig, x, y, name, fields):
	'''draw tabletop'''

	#  (NB: y grows downward)
	txt = TextElement(x, y, name, True)
	tt = TabletopElement(x, y)
	image_map[name] = {'coord': (x, y), 'def': '', 'descr': ''}
	fig.append(sg.GroupElement([tt, txt]))
	for f in fields:
		y += RECT_HEIGHT
		fig.append(add_field(x, y, f, name))

# get arguments
args = docopt(__doc__)

# create new SVG figure
fig = sg.SVGFigure('%.5fin' % (FIG_WIDTH/DOTS_PER_INCH), '%.5fin' % (FIG_HEIGHT/DOTS_PER_INCH))
fig.append(background.getroot())

# read tables and fields
# expect create statement with one field matching re like so:
f = open(args['--sql'], 'r')
begin_table = re.compile(r'^\s*CREATE TABLE\s*([a-z_]+)')
end_table = re.compile(r'^\)$')
field = re.compile(r'^\s*([a-z_]+)\s+(.*)')

table_name = False
fields = [] # list of 2-tuples
for sql_line in f:
	if table_name:
		if end_table.match(sql_line):
			co = table_coord[table_name]
			# print "table %s " % table_name, "at (%f, %f)" % co, fields, "\n"
			add_table(fig, co[0], co[1], table_name, fields)
			table_name = False
			fields = []
			continue

		mo = field.search(sql_line)
		if mo == None:
			continue

		# name, definition
		fields.append((mo.group(1), mo.group(2)))

	else:
		mo = begin_table.search(sql_line)
		if mo == None:
			continue

		table_name = mo.group(1)
f.close()

# add template
if args.get('--svg', False):
	templ = sg.fromfile(args['--svg'])
	fig.append(templ.getroot())

# save generated SVG file
fig.save(args['--out'] + '.svg')


###########################################
from perlpod import pod2html

# look up X marks
podmark = re.compile(r'[IBCLEFSXZ]<([^<>]*)>')
def pod2fields(pod):
	'''handle titles with encoded terms'''
	fields = ''
	for mo in podmark.finditer(pod):
		if fields and mo.group(1):
			fields += ' '
		fields += mo.group(1)
	return fields

# read table and field descriptions
def add_descr(anchor, descr):
	assert image_map.get(anchor, False), 'Bad anchor: '+ anchor
	if descr.endswith(','):
		descr = descr[:len(descr) - 1]
	image_map[anchor]['descr'] += descr.strip()

# grab "=head1 INSTALLATION" for intro;
# paragraphs tagged "=item <fields>X<tables>" go in the relevant descr;
item = re.compile(r'^=item\s*([^X]*)\s*X<([a-z_ ]+)>')
new_para = re.compile(r'^=([a-z]+[1-4]?)\s+([^X]*)')

def read_pod(fname):
	# global item, new_para
	f = open(fname, 'r')
	depth = 0
	tables = False
	fields = False
	class para_dd: pass
	para_dd.pending = False
	para_dd.para = ''
	def close_dd():
		if para_dd.pending:
			para_dd.para += '</dd>'
			para_dd.pending = False

	for pod_line in f:
		if pod_line.strip() == '':
			continue

		for line in f:
			if line.strip() == '':
				break
			pod_line += line

		mo = new_para.search(pod_line)
		if mo:
			verb = mo.group(1)
			if tables or intro.track:
				if verb == 'over':
					depth += 1
					para_dd.para += '<dl>'
					continue

				if verb == 'back' and depth > 0:
					depth -= 1
					close_dd()
					para_dd.para += '</dl>'
					continue

				if verb == 'item' and depth > 0 and mo.group(2):
					close_dd()
					dt_class = 'table_dt' if intro.track else 'inner_dt'
					para_dd.para += '\n<dt class="%s">' % dt_class + pod2html(mo.group(2)) + '</dt><dd>'
					para_dd.pending = True
					continue

				if para_dd.para:
					close_dd()
					if tables:
						for table in tables:
							if fields:
								for field in fields:
									add_descr(table +'-'+ field, para_dd.para)
							else:
								add_descr(table, para_dd.para)
					else:
						intro.para += para_dd.para.strip()
					para_dd.para = ''

			if verb.startswith('head') and verb[4:5] in ('1', '2', '3', '4'):
				lv = 1 + int(verb[4:5])
				title = mo.group(2).strip()
				if title in ('INSTALLATION', 'TABLES', 'TABLES MEANING'):
					intro.track = True
					intro.para += '\n<h%d>%s</h%d>\n' % (lv, title.capitalize(), lv)
				else:
					intro.track = False

			mo = item.search(pod_line)
			if mo:
				fields = filter(bool, re.split(r'\W+', pod2fields(mo.group(1))))
				tables = filter(bool, re.split(r'\W+', mo.group(2)))
				# print fname + ' -> fields(', fields, ') and tables(', tables, ')'
				intro.track = False
			else:
				tables = False
				fields = False
		elif tables or intro.track:
			para_dd.para += pod2html(pod_line)
	f.close()

for fname in args['--pod']:
	read_pod(fname)

# export svg to png
dots_per_inch = float(args['--dpi'])
do_css = not args.get('--image-map', False)
def mapped_unit(f):
	''' return float em's for css, int px'es for image map'''
	if do_css:
		return (f*dots_per_inch)/(16.0*DOTS_PER_INCH)
	return int(0.5 + (f*dots_per_inch)/DOTS_PER_INCH)

subprocess.check_output(['inkscape', '--export-png=%s.png' % args['--out'],
	'--export-dpi=' + args['--dpi'], '--export-area-page', args['--out'] + '.svg'],
	stderr=subprocess.STDOUT)

# name referenced from html
base_ref = os.path.basename(args['--out'])

# write html
html_fname = args['--out-html']
if not html_fname:
	html_fname = args['--out'] + '.html'
out = open(html_fname, 'w')

def write_html():
	'''generate code based on global variables'''
	if do_css:
		# cannot have anchors inside anchors (had better not adding them in the first place)
		rm_a_start = re.compile(r'<a[^>]+>')
		out.write('<div id="dbgraph">\n')
		for k in image_map:
			out.write('\t<div class="dbgraph" id="%s-def"><a href="#%s"><div>\n' % (k, k))
			k_dash = k.find('-')
			def_body = rm_a_start.sub('',
				image_map[k]['descr'].replace('</a>', '').replace('\n', '\n\t\t\t'))
			if k_dash < 0:
				out.write('\t\t<h4>table %s</h4>\n\t\t<p>%s' %
				(
					k, def_body 
				))
			else:
				out.write('\t\t<h5>%s <span>%s</span></h5>\n\t\t<p>%s' %
				(
					k[k_dash+1:], cgi.escape(image_map[k]['def']), def_body
				))
			out.write('\n\t</div></a></div>\n')
		out.write('</div>')
	else:
		out.write('<img src="%s.png" alt="Database scheme" usemap="#dbgraph" />\n' % base_ref)
		out.write('\n')
		out.write('<map name="dbgraph">\n')
		for k in image_map:
			el = image_map[k]
			coord = el['coord']
			out.write('\t<area shape="rect" coords="%d,%d,%d,%d" href="#%s" title="%s">\n' %
				(
					mapped_unit(coord[0]),
					mapped_unit(coord[1]),
					mapped_unit(coord[0] + RECT_WIDTH),
					mapped_unit(coord[1] + RECT_HEIGHT),
					k,
					cgi.escape(el['def'], True)
				))
		out.write('</map>')
	out.write('\n')

	# intro
	out.write('<div class="box">\n\t<p>\n\t%s\n</div>\n' %
		(intro.para.replace('\n', '\n\t\t')))

	table = ''
	one_dl_per_table = True
	def close_table():
		if table:
			if one_dl_per_table:
				out.write('\t</dl>\n')
			out.write('</div>\n')

	for k in sorted(image_map.keys()):
		descr = image_map[k]['descr']
		k_dash = k.find('-')
		if k_dash < 0:
			close_table()
			table = k
			out.write('\n<h2 id="%s">table %s</h2>\n<div class="box">\n' % (k, k))
			if descr:
				out.write('\t<p>\n\t\t%s\n' % (descr.replace('\n', '\n\t\t')))
			if one_dl_per_table:
				out.write('\t<dl>\n')
			else:
				out.write('\n')
		else:
			assert table == k[:k_dash], 'Wrong keys order: %s on %s' % (k, table)
			if not one_dl_per_table:
				out.write('\t<dl>\n')
			out.write('\t\t<dt id="%s" class="field_dt">%s</dt>\n\t\t<dd>\n\t\t\t%s\n\t\t</dd>' %
				(k, k[k_dash + 1:], descr.replace('\n', '\n\t\t\t')))
			if not one_dl_per_table:
				out.write('\n\t</dl>')
			out.write('\n')

	close_table()
	out.write('\n')

def write_css():
	''' write inline definitions; see:
	http://frankmanno.com/ideas/css3-imagemap/ '''

	out.write('<style type="text/css">\n')
	out.write('''\tdiv#dbgraph{
		border-width: 0 0.2em 0.2em 0.2em;
		border-style: solid;
		border-color: #FFCC66;
		margin: 0 0.8em 0.8em 0.8em;
		padding: 0;
		background: #FFCC66 url(%s.png) top left / 100%% auto no-repeat;
		width: %.5fem;
		height: %.5fem;
		position: relative;
		float: left;
		/* box-shadow: 0 0 5px rgba( 0, 0, 0, 0.5 ); */
		/* border: 5px solid #fff; */
	}\n''' % (base_ref, mapped_unit(FIG_WIDTH), mapped_unit(FIG_HEIGHT)))

	out.write('''\tdiv.dbgraph a {
		width: %.5fem;
		height: %.5fem;
		position: absolute;
		/*
		outline: none;
		text-decoration: none;
		border: 1px solid #FFFCE6;
		background: rgba( 255, 255, 191, 0.4 );
		text-shadow: 0 1px 0 rgba( 255, 255, 255, 0.9 );

		-webkit-transition: background 1s ease-in-out, border 1s ease-in-out;
		-moz-transition: background 1s ease-in-out, border 1s ease-in-out;
		-o-transition: background 1s ease-in-out, border 1s ease-in-out;
		-ms-transition: background 1s ease-in-out, border 1s ease-in-out;
		transition: background 1s ease-in-out, border 1s ease-in-out;
		*/
	}\n''' % (mapped_unit(RECT_WIDTH), mapped_unit(RECT_HEIGHT)))

	out.write('''\tdiv.dbgraph a:hover{
		background: rgba( 255, 255, 255, 0 );
		border: 1px solid transparent;
	}

	div.dbgraph a:active{
		outline: none;
	}\n''')

	out.write('''\th4 {
		width: %.5fem;
		font-weight: bold;
		font-size: 120%%;
		margin: 0;
	}\n''' % mapped_unit(FIG_WIDTH/1.618))

	out.write('''\th5 {
		font-weight: bold;
		font-size: 112%;
		white-space: nowrap;
		margin: 0;
	}

	h5 span {
		font-family: monospace;
		font-weight: normal;
		font-size: 60%;
	}

	div.dbgraph a div{
		opacity: 0;
		visibility: hidden;
		position: absolute;
		left: -1px;
		z-index: inherit;
		top: 0;
		/*
		height: 20px;
		line-height: 20px;
		text-indent: 0;
		vertical-align: top;
		*/
		background-color: #FFEEAA;
		border: 1px solid #003300;
		margin: 0;
		padding: 0.3em;
		box-shadow: 0 0px 5px rgba( 0, 0, 0, 0.5 );

		-webkit-transition: all 1s ease-in-out;
		-moz-transition: all 1s ease-in-out;
		-o-transition: all 1s ease-in-out;
		-ms-transition: all 1s ease-in-out;
		transition: all 1s ease-in-out;
	}

/*
	div.dbgraph a div:after{
		border: 10px solid #F4F4F4;
		width: 0;
		height: 0;
		content: '';
		position: absolute;
		border-color: #F4F4F4 transparent transparent;
		left: 5px;
		bottom: -21px;
		opacity: 1;
	}
*/
	div.dbgraph a:hover div, div.dbgraph a:focus div{
		visibility: visible;
		opacity: 1;
		z-index: 1234;
		/*
		top: -45px;
		*/
	}\n''')

	for k in image_map:
		coord = image_map[k]['coord']
		out.write('\tdiv.dbgraph#%s-def a { left: %.5fem; top: %.5fem; }\n' %
			(
				k,
				mapped_unit(coord[0]),
				mapped_unit(coord[1])
			))
	out.write('</style>\n')


if args.get('--txt', None):
	html_templ = open(args['--txt']);
	for html_line in html_templ:
		out.write(html_line)
		if do_css and html_line.find('<!-- dbgraph css -->') >= 0:
			write_css()
		if html_line.find('<!-- dbgraph -->') >= 0:
			write_html()
	html_templ.close()

out.close();
