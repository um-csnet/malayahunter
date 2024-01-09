---
title: Steps for writeups
author: [capang,shafiq]
date: 2024-01-01 09:30:00 +0800
categories: [Documentation, Tutorial]
tags: [Documentation]
pin: true
render_with_liquid: false
---

This tutorial will guide you how to write a post in using Markdown Format

- Set File Name

Create a new file named `YYYY-MM-DD-TITLE.EXTENSION` and put it in the `_posts`. Please note that the `EXTENSION`{: .filepath} must be one of `md`{: .filepath} and `markdown`{: .filepath}.

Example

`2024-01-03-chall1.md` File name for a writeup on challenge named chal1 on 03/01/2024

- Set Front Matter

```yaml
---
title: TITLE
date: YYYY-MM-DD HH:MM:SS +/-TTTT
categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [TAG]     # TAG names should always be lowercase
---
```

This will set what ur contents is all about

Example for challenge Magic Door in PWN Category during Wargames 2023 on 01/01/2024 written by `capang`

```yaml
---
title: Magic Door
author: capang
date: 2024-01-01 09:30:00 +0800
categories: [Writeups, PWN]
tags: [wargames 2023]
math: true
mermaid: true
---
```

- Register Author Information 

Adding author information in `_data/authors.yml`

```yaml
<author_id>:
  name: <full name>
  twitter: <twitter_of_author>
  url: <homepage_of_author>
```
{: file="_data/authors.yml" }

Example

```yaml
capang:
  name: Capang
  twitter: 
  url: https://github.com/broCapang

shafiq:
  name: Shafiq
  twitter: 
  url: https://github.com/shafiqps
```

And then use `author` to specify a single entry or `authors` to specify multiple entries:

```yaml
---
author: <author_id>                     # for single entry
# or
authors: [<author1_id>, <author2_id>]   # for multiple entries
---
```

- Include challenge file for people to download

`[Download Source File]({{site.url}}/assets/files/road_not_taken.zip)`

Example

[Download Source File]({{site.baseurl}}/assets/files/road_not_taken.zip)

> If you lost the challenge file, make sure to point out where people can get the challenge file
{: .prompt-info }



