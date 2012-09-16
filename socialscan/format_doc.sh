#!/bin/bash 

output=docs_site
input=docs
markdown=/home/lahwran/Downloads/Markdown_1.0.1/Markdown.pl

rm -rf $output
mkdir -p $output
cp -r $input/* $output




echo "Index" >> $output/index
echo "-----" >> $output/index
echo >> $output/index

for f in $output/*.md
do
	name="$(basename "$f" .md)"
	echo "- [$name]($name.html)" >> $output/index
done

echo >> $output/index
echo >> $output/index
echo "Epydoc" >> $output/index
echo "-----" >> $output/index
echo >> $output/index
echo "- **[generated documentation](epydoc/module-tree.html)**" >> $output/index
echo "- [generated documentation (frames)](epydoc/index.html)" >> $output/index

mv $output/index $output/index.md

for f in $output/*.md
do
	name="$(basename "$f" .md)"
    file="$output/$name.html"
	echo "<DOCTYPE html><html><head><title>$name</title></head><body>" > "$file"
	$markdown < "$f" >> "$file"
	echo '<div id="footer"><a href="index.html">index</a></div>' >> "$file"
	echo "</body></html>" >> "$file"
	rm "$f"
done

epydoc -vo docs_site/epydoc/ --name socialscan main redirector testutils socialscan
