#!/bin/bash
folder="${1:-./}"
shopt -s globstar
output_file="output.txt"
rm -f "$output_file"    # Remove the old output file if it exists
touch "$output_file"    # Create a new empty output file

for file in "$folder"/**/*.{js,yml,json,html,j2}; do
  [[ -f "$file" ]] || continue
  echo "$file:" >> "$output_file"
  cat "$file" >> "$output_file"
  echo "---------------------" >> "$output_file"
done
