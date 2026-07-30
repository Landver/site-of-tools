package site

import (
	"encoding/json"
	"html/template"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// Author identity. Single source for the `author` meta tag and the JSON-LD
// Person, so a search engine or an AI answer attributes a post to a stable
// entity rather than to whoever syndicated it. Profile links are the
// `sameAs` anchors that tie this Person to accounts elsewhere.
const (
	authorName    = "Stas"
	authorProfile = "https://www.linkedin.com/in/stanislav-navarici/"
)

// sitemapPages lists the apex's indexable URLs: landing, blog index, and one
// entry per published post. lastmod on the two static pages tracks the newest
// post, so publishing re-dates the pages that link to it. Drafts never reach
// here — LoadPosts filters them first.
//
// Method on Blog (not a package func) so platform.RegisterSEO can take it as
// a per-request closure and pick up dev's live reload for free.
func (b *Blog) sitemapPages() ([]platform.Page, error) {
	posts, err := b.posts()
	if err != nil {
		return nil, err
	}
	var newest time.Time
	if len(posts) > 0 {
		newest = posts[0].Date
	}
	pages := []platform.Page{
		{Path: "/", LastMod: newest},
		{Path: "/blog", LastMod: newest},
	}
	for _, p := range posts {
		pages = append(pages, platform.Page{Path: "/blog/" + p.Slug, LastMod: p.Date})
	}
	return pages, nil
}

// --- JSON-LD ----------------------------------------------------------------

type ldPerson struct {
	Type   string   `json:"@type"`
	Name   string   `json:"name"`
	URL    string   `json:"url"`
	SameAs []string `json:"sameAs,omitempty"`
}

type ldWebPage struct {
	Type string `json:"@type"`
	ID   string `json:"@id"`
}

type ldBlogPosting struct {
	Context          string    `json:"@context"`
	Type             string    `json:"@type"`
	Headline         string    `json:"headline"`
	Description      string    `json:"description,omitempty"`
	Image            string    `json:"image,omitempty"`
	DatePublished    string    `json:"datePublished"`
	DateModified     string    `json:"dateModified"`
	URL              string    `json:"url"`
	MainEntityOfPage ldWebPage `json:"mainEntityOfPage"`
	Author           ldPerson  `json:"author"`
	Publisher        ldPerson  `json:"publisher"`
	InLanguage       string    `json:"inLanguage"`
}

// articleJSONLD builds the schema.org BlogPosting for one post. Returns
// template.JS so html/template drops it into the ld+json script tag verbatim
// instead of escaping the JSON — safe because every field is our own
// committed content, marshalled by encoding/json.
//
// postURL and imageURL must be absolute; relative URLs are silently ignored
// by consumers, which is the kind of bug that only shows up in a validator.
func articleJSONLD(post Post, postURL, imageURL, base string) (template.JS, error) {
	// Date-only frontmatter → RFC3339 at UTC midnight. Posts are not revised
	// in place, so modified tracks published.
	published := post.Date.UTC().Format(time.RFC3339)
	me := ldPerson{
		Type:   "Person",
		Name:   authorName,
		URL:    base,
		SameAs: []string{authorProfile},
	}
	doc := ldBlogPosting{
		Context:          "https://schema.org",
		Type:             "BlogPosting",
		Headline:         post.Title,
		Description:      post.Desc,
		Image:            imageURL,
		DatePublished:    published,
		DateModified:     published,
		URL:              postURL,
		MainEntityOfPage: ldWebPage{Type: "WebPage", ID: postURL},
		Author:           me,
		Publisher:        me,
		InLanguage:       "en",
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return template.JS(out), nil
}
