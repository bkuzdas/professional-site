import { defineCollection, z } from 'astro:content';

const articles = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    pubDate: z.date(),
    category: z.string(),
    tags: z.array(z.string()),
    coverImage: z.string().optional(),
    linkedinUrl: z.string().optional(),
    published: z.boolean().default(false),
    featured: z.boolean().default(false),
  }),
});

export const collections = { articles };
