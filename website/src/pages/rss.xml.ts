import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';
import type { APIContext } from 'astro';
import { url } from '../lib/base';

export async function GET(context: APIContext) {
  const posts = (await getCollection('blog', ({ data }) => !data.draft)).sort(
    (a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf(),
  );
  const siteRoot = context.site ?? new URL('https://openshield-org.github.io');
  return rss({
    title: 'OpenShield Blog',
    description:
      'Release notes, engineering deep-dives and integration guides from the OpenShield maintainers.',
    site: new URL(url('/'), siteRoot),
    stylesheet: url('/rss.xsl'),
    items: posts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.pubDate,
      description: post.data.description,
      author: post.data.author,
      categories: post.data.tags,
      link: url(`/blog/${post.id}/`),
    })),
  });
}
