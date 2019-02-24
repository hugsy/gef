## Command highlight ##

This command sets up custom highlighting for user set strings.

Syntax:

```
highlight (add|remove|list|clear)
```

Alias:

  - `hl`

## Adding matches

The following will add `41414141`/`'AAAA'` as yellow, and `42424242`/`'BBBB'`
as blue:

```
gef➤  hl add 41414141 yellow
gef➤  hl add 42424242 blue
gef➤  hl add AAAA yellow
gef➤  hl add BBBB blue
```

## Removing matches

To remove a match, target it by the original string used, ex.:

```
gef➤  hl rm 41414141
```

## Listing matches

To list all matches with their colors:

```
gef➤  hl list
41414141 | yellow
42424242 | blue
AAAA     | yellow
BBBB     | blue
```

## Clearing all matches

To clear all matches currently setup:

```
gef➤  hl clear
```

## RegEx support

RegEx support is disabled by default, this is done for performance reasons.

To enable regular expressions on text matches:

```
gef➤  gef config highlight.regex True
```

To check the current status:

```
gef➤  gef config highlight.regex
highlight.regex (bool) = True
```

## Performance

_**NOTE:** Adding many matches may slow down debugging while using GEF.
This includes enabling RegEx support._

## Colors

To find a list of supported colors, check the
[theme](./theme.md#changing-colors) documentation.

