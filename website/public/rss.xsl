<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html" version="1.0" encoding="UTF-8" indent="yes"/>
<xsl:template match="/rss">
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title><xsl:value-of select="channel/title"/> / RSS</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#f2f0ec;color:#050505;font-family:'Schibsted Grotesk',system-ui,-apple-system,sans-serif;font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
.mono,.kicker,.meta,.date{font-family:'DM Mono',ui-monospace,monospace}
a{color:inherit;text-decoration:none}
:focus-visible{outline:2px solid #f3441d;outline-offset:2px;border-radius:6px}
.wrap{max-width:860px;margin:0 auto;padding:56px 24px 72px}
.kicker{font-size:12px;letter-spacing:.08em;color:#636366;text-transform:uppercase;margin-bottom:12px}
h1{font-size:40px;line-height:1.08;font-weight:800;letter-spacing:-.03em}
.sub{color:#636366;margin-top:10px;font-size:15.5px;max-width:62ch}
.meta{margin-top:18px;font-size:11px;letter-spacing:.06em;color:#f3441d;text-transform:uppercase}
.list{margin-top:34px;border-top:1px solid #d3d2d2}
.item{display:block;padding:20px 4px;border-bottom:1px solid #d3d2d2;transition:background .15s}
.item:hover{background:#ffffff}
.date{display:block;font-size:11px;letter-spacing:.06em;color:#636366;text-transform:uppercase}
.t{display:block;font-size:18px;font-weight:700;letter-spacing:-.015em;margin-top:5px}
.item:hover .t{color:#f3441d}
.d{display:block;font-size:14px;color:#636366;margin-top:4px}
.foot{margin-top:26px;font-size:11px;letter-spacing:.05em;color:#636366}
.foot a{color:#f3441d}
</style>
</head>
<body>
<div class="wrap">
  <div class="kicker">RSS 2.0 / machine-readable feed</div>
  <h1><xsl:value-of select="channel/title"/></h1>
  <p class="sub"><xsl:value-of select="channel/description"/></p>
  <p class="meta"><xsl:value-of select="count(channel/item)"/> entries / paste this page's URL into any feed reader</p>
  <div class="list">
    <xsl:for-each select="channel/item">
      <a class="item">
        <xsl:attribute name="href"><xsl:value-of select="link"/></xsl:attribute>
        <span class="date"><xsl:value-of select="pubDate"/></span>
        <span class="t"><xsl:value-of select="title"/></span>
        <span class="d"><xsl:value-of select="description"/></span>
      </a>
    </xsl:for-each>
  </div>
  <p class="foot">You are reading the styled view of an XML feed. The raw XML is what your reader consumes. <a><xsl:attribute name="href"><xsl:value-of select="channel/link"/></xsl:attribute>Back to the site</a></p>
</div>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
