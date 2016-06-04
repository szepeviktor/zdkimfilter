#! /bin/sh
# usually sourced from the etc distribution dir where it resides
# after configure and make build relevant files

webdir=~www/sw/zdkimfilter
if [ "$1" = "save" ]; then
	echo "Saving current web files"
	zipfile="$(pwd)/$(date +web%Y%m%d-%H%M%S.zip)"
	pushd "$webdir"
	zip -jon .png "$zipfile" *.html *.shtml *.css fig_final.png
	popd
fi

man2html zfilter_db.1 |perl mangle_doc.pl h1 zfilter_db_snippet.html
man2html zdkimfilter.conf.5 |perl mangle_doc.pl h1
man2html zdkimfilter.8 |perl mangle_doc.pl h1
man2html dkimsign.1 |perl mangle_doc.pl h1
man2html redact.1 |perl mangle_doc.pl h1
man2html zaggregate.1 | perl mangle_doc.pl h1

cp ${webdir}/index.shtml ./temp-index.bak
cat ${webdir}/index.shtml | perl mangle_doc.pl web 0 > temp-index
cp temp-index ${webdir}/index.shtml
cp ${webdir}/v-0.5.html ./temp-0.5.bak
cat ${webdir}/v-0.5.html | perl mangle_doc.pl web 1 > temp-0.5
cp temp-0.5 ${webdir}/v-0.5.shtml

python dbgraph.py \
	--sql=../odbx_example.sql \
	--pod=zfilter_db.pod --pod=odbx_example.pod \
	--txt=dbtemplate.html \
	--svg=dbtemplate.svg \
	--out ${webdir}/fig_final --out-html temp-db
cat temp-db |perl mangle_doc.pl web 2 > ${webdir}/database.html

