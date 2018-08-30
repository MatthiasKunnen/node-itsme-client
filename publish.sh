#!/usr/bin/env bash

echo "What type of publish?"
select version_type in "patch" "minor" "major"; do
    if [ -z "$version_type" ]; then
        echo "Invalid, enter type number or CTRL + C to quit."
        continue
    fi

    # Use npm to increment the version and capture it
    version=`npm version ${version_type} --git-tag-version=false` || exit "$?"

    # Get last tag
    last_tag=`git describe --abbrev=0 2>/dev/null`..HEAD

    if [ "$?" -ne  "0" ]; then
        echo "There is no previous tag, assuming first publication"
        last_tag=`git rev-list --max-parents=0 HEAD` || exit "$?"
    fi

    changelog=`git log --format="- %s%+b" ${last_tag}`
    message="Bumped package version to $version"

    echo "Message:"
    echo -e "$message"
    read -p "Examine message. [Enter] to continue"

    echo ""
    echo "Changelog:"
    echo -e "$changelog"
    read -p "Examine changelog. [Enter] to continue"

    read -p "Creating commit and tag for a $version_type release ($version). Press [Enter].";

    git add package.json package-lock.json || exit "$?"
    git commit -m "$message" || exit "$?"

    tag_args=(
        -a
        -m "Released $version"
        -m "$changelog"
    )

    signing_key=`git config --get user.signingKey`

    if [ -n "$signing_key" ]; then
        echo "Found key, signing..."
        tag_args+=(-s)
    fi

    git tag "${version}" "${tag_args[@]}" || exit "$?"

    rm -Rf dist
    echo "Building"
    npm run build || exit "$?"
    cp ./package.json ./.npmignore ./README.md ./dist || exit "$?"
    cd dist || exit "$?"

    read -p "Ready to publish?; [Enter] to continue";
    npm publish || exit "$?"
    break
done
