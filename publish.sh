#!/usr/bin/env bash

if output=$(git status --untracked-files=no --porcelain) && [ -n "$output" ]; then
    echo The working directory is not clean!
    exit 1
fi

echo "What type of publish?"
select version_type in "patch" "minor" "major"; do
    if [ -z "$version_type" ]; then
        echo "Invalid, enter type number or CTRL + C to quit."
        continue
    fi

    # Use npm to increment the version and capture it
    version=`npm version ${version_type} --git-tag-version=false` || exit "$?"

    # Get last tag
    last_tag=`git describe --abbrev=0 2>/dev/null`

    if [ "$?" -ne  "0" ]; then
        echo "There is no previous tag, assuming first publication"
        last_tag=`git rev-list --max-parents=0 HEAD` || exit "$?"
    fi

    changelog=`git log --no-merges --pretty=tformat:"- %s%n%w(100,2,2)%-b" ${last_tag}..HEAD`
    message="Bumped package version to $version"

    echo "Message:"
    echo -e "$message"
    read -p "Examine message. [Enter] to continue"

    echo ""
    echo "Changelog:"
    echo -e "$changelog"
    echo "${changelog}" > CHANGELOG_MSG
    read -p "Examine changelog, edit CHANGELOG_MSG if desired. [Enter] to continue"
    changelog="$(<CHANGELOG_MSG)"
    rm -f CHANGELOG_MSG

    read -p "Creating commit and tag for a $version_type release ($version). Press [Enter].";

    git add package.json || exit "$?"
    git commit -m "$message" || exit "$?"

    tag_args=(
        -a
        -m "$changelog"
    )

    signing_key=`git config --get user.signingKey`

    if [ -n "$signing_key" ]; then
        echo "Found key, signing..."
        tag_args+=(-s)
    fi

    git tag "${version}" "${tag_args[@]}" || exit "$?"

    echo "Building"
    yarn run build || exit "$?"

    read -p "Ready to publish?; [Enter] to continue";
    npm publish || exit "$?"
    git push --follow-tags
    break
done
