package site

import (
	"encoding/json"
	"html/template"
	"time"

	"github.com/Landver/site-of-tools/platform"
)

// One author identity for the meta tag and JSON-LD Person, so posts attribute to a stable entity.
const (
	authorName    = "Stas"
	authorProfile = "https://www.linkedin.com/in/stanislav-navarici/"
)

// sitemapPages dates the landing and blog index by the newest post; as a Blog method it sees dev reloads.
func (b *Blog) sitemapPages() ([]platform.Page, error) {
	posts, err := b.Posts()
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

// articleJSONLD returns template.JS so the JSON isn't escaped, safe as every field is our own content.
// postURL and imageURL must be absolute: consumers silently ignore relative ones.
func articleJSONLD(post Post, postURL, imageURL, base string) (template.JS, error) {
	// Posts aren't revised in place, so modified tracks published.
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
