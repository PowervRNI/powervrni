#!/bin/bash

echo "# PowervRNI - Examples" > EXAMPLES.md

EXAMPLE_FILES="examples/*.ps1 examples/archive-flows-to-vrli/*.ps1"
for example in $EXAMPLE_FILES
do
    #echo "Processing $example file..."
    # see if example header is present
    LINE=`grep "Example:" $example`
    if [ -n "$LINE" ]
    then
        EXAMPLE_NAME=`echo $LINE | sed -e 's/^# Example:\ *//'`
        echo "## ${example}" >> EXAMPLES.md
        echo "### ${EXAMPLE_NAME}" >> EXAMPLES.md

        # sed -n '1!p' = cut first line ("START Description")
        # sed '$d' = cut last line ("END Description")
        # sed 's/^..//' = remove the comments "# "
        EXAMPLE_DESC=`sed -n '/START Description/,/END Description/p' $example | sed -n '1!p' | sed '$d' | sed 's/^..//'`
        echo $EXAMPLE_DESC >> EXAMPLES.md

        example_file=`echo $example | sed -e 's/^examples\/\ *//'`

        #echo "<tr>"
        #echo "    <td class=\"left\">${example_file}</td>"
        #echo "    <td class=\"left\">${EXAMPLE_NAME}</td>"
        #echo "    <td class=\"left\">${EXAMPLE_DESC}</td>"
        #echo "</tr>"
    fi
done