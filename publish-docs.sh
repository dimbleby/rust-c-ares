#!/bin/bash
set -e

cargo doc -p c-ares
echo "<meta http-equiv=refresh content=0;url=c_ares/index.html>" > target/doc/index.html

git config user.name "Travis CI"
pip install --user ghp-import
~/.local/bin/ghp-import -n target/doc

openssl aes-256-cbc -K "$encrypted_eab4824118db_key" -iv "$encrypted_eab4824118db_iv" -in publish-key.enc -out ~/.ssh/publish-key -d
chmod u=rw,og= ~/.ssh/publish-key
echo "Host github.com" >> ~/.ssh/config
echo "  IdentityFile ~/.ssh/publish-key" >> ~/.ssh/config
git remote set-url origin git@github.com:dimbleby/rust-c-ares.git
git push origin +gh-pages
