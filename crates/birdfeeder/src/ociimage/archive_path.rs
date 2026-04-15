//! Names of layer entries. Tar names don't have to be UTF-8, so we keep them as bytes. They compare lexically,
//! since that's how the OCI layer rules match whiteouts and overrides against lower layers' files.

use std::fmt;

/// An entry name with `.`, `..` and doubled slashes cleaned out, relative to the image root (the empty path).
/// Layers don't agree on a leading slash, so whiteouts and overrides all compare this one form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArchivePath(Vec<u8>);

/// A name that climbs out of the image root (or would on Windows), shown cleaned up.
#[derive(Debug, thiserror::Error)]
#[error("{:?}", String::from_utf8_lossy(.0))]
pub struct Escapes(Vec<u8>);

impl ArchivePath {
    pub fn parse(raw: &[u8]) -> Result<Self, Escapes> {
        let clean = Cleaned::new(raw.starts_with(b"/"), 0, raw.split(|&b| b == b'/'));
        // on Windows an extractor would treat backslashes as separators and a drive letter as a new root.
        let windows = Cleaned::new(clean.rooted, clean.ups, clean.parts.iter().flat_map(|p| p.split(|&b| b == b'\\')));
        let leading_backslash = !clean.rooted && clean.parts.first().is_some_and(|p| p.starts_with(b"\\"));
        let drive = !windows.rooted && windows.parts.first().is_some_and(|p| p.len() >= 2 && p[0].is_ascii_alphabetic() && p[1] == b':');
        if windows.ups > 0 || leading_backslash || drive {
            return Err(Escapes(clean.to_bytes()));
        }
        Ok(Self(clean.parts.join(&b'/')))
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The directory holding this name, or None for the root.
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        Some(Self(self.0.iter().rposition(|&b| b == b'/').map_or_else(Vec::new, |i| self.0[..i].to_vec())))
    }

    /// The last component, empty for the root.
    pub fn file_name(&self) -> &[u8] {
        self.0.iter().rposition(|&b| b == b'/').map_or(&self.0, |i| &self.0[i + 1..])
    }

    /// The entry name inside this directory, or None when name isn't a single component.
    pub fn join(&self, name: &[u8]) -> Option<Self> {
        if matches!(name, b"" | b"." | b"..") || name.contains(&b'/') {
            return None;
        }
        Some(Self(if self.is_root() { name.to_vec() } else { [&self.0[..], b"/", name].concat() }))
    }

    /// Whether other lies strictly inside this directory.
    pub fn contains(&self, other: &Self) -> bool {
        other.0.len() > self.0.len() && other.0.starts_with(&self.0) && (self.is_root() || other.0[self.0.len()] == b'/')
    }

    /// The parent, its parent, and so on up to the root.
    pub fn ancestors(&self) -> impl Iterator<Item = Self> {
        std::iter::successors(self.parent(), Self::parent)
    }
}

impl fmt::Display for ArchivePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

/// A name's components with empty ones, `.`, and `..` resolved lexically.
struct Cleaned<'a> {
    rooted: bool,
    /// leading `..` components, which only an unrooted name keeps.
    ups: usize,
    parts: Vec<&'a [u8]>,
}

impl<'a> Cleaned<'a> {
    fn new(rooted: bool, ups: usize, components: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut c = Self { rooted, ups, parts: Vec::new() };
        for part in components {
            match part {
                b"" | b"." => {}
                b".." => {
                    if c.parts.pop().is_none() && !rooted {
                        c.ups += 1;
                    }
                }
                _ => c.parts.push(part),
            }
        }
        c
    }

    fn to_bytes(&self) -> Vec<u8> {
        let parts: Vec<&[u8]> = std::iter::repeat_n(&b".."[..], self.ups).chain(self.parts.iter().copied()).collect();
        match (self.rooted, parts.join(&b'/')) {
            (true, joined) => [b"/", &joined[..]].concat(),
            (false, joined) if joined.is_empty() => b".".to_vec(),
            (false, joined) => joined,
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn parse(name: &str) -> Result<String, String> {
        ArchivePath::parse(name.as_bytes()).map(|p| p.to_string()).map_err(|e| String::from_utf8(e.0).unwrap())
    }

    #[rstest]
    #[case::empty("", Ok(""))]
    #[case::dot_slash("./", Ok(""))]
    #[case::root("/", Ok(""))]
    #[case::trailing_slash("./etc/", Ok("etc"))]
    #[case::doubled_slash_dot_and_dotdot("a//b/./c/..", Ok("a/b"))]
    #[case::dotdot_at_root("/../x", Ok("x"))]
    #[case::absolute("/abs/file", Ok("abs/file"))]
    #[case::dotdot_prefixed_name("..foo/bar", Ok("..foo/bar"))]
    #[case::dotdot_prefixed_top_level_name("..etc", Ok("..etc"))]
    #[case::dotdot("..", Err(".."))]
    #[case::climbing("../etc", Err("../etc"))]
    #[case::leading_dotdots("../../x", Err("../../x"))]
    #[case::climbing_past_start("a/../../b", Err("../b"))]
    #[case::drive_letter("C:/x", Err("C:/x"))]
    #[case::leading_backslash("\\x", Err("\\x"))]
    #[case::climbing_by_backslash("a\\..\\..\\b", Err("a\\..\\..\\b"))]
    #[case::backslash_inside_a_rooted_name("/\\x", Ok("\\x"))]
    fn parses(#[case] name: &str, #[case] want: Result<&str, &str>) {
        assert_eq!(parse(name), want.map(str::to_owned).map_err(str::to_owned));
    }

    #[rstest]
    #[case::nested("a/b/c", Some("a/b"))]
    #[case::top_level("c", Some(""))]
    #[case::absolute_top_level("/c", Some(""))]
    #[case::root("/", None)]
    fn parents(#[case] name: &str, #[case] want: Option<&str>) {
        let parent = ArchivePath::parse(name.as_bytes()).unwrap().parent();
        assert_eq!(parent.map(|p| p.to_string()).as_deref(), want);
    }

    #[rstest]
    #[case::trailing_slash("a/b/", "b")]
    #[case::top_level("a", "a")]
    #[case::root("/", "")]
    fn file_names(#[case] name: &str, #[case] want: &str) {
        assert_eq!(ArchivePath::parse(name.as_bytes()).unwrap().file_name(), want.as_bytes());
    }

    #[rstest]
    #[case::onto_root("", "x", Some("x"))]
    #[case::onto_dir("bin", "x", Some("bin/x"))]
    #[case::climbing("bin", "../../outside", None)]
    #[case::dotdot("bin", "..", None)]
    #[case::dot("bin", ".", None)]
    #[case::empty("bin", "", None)]
    fn joins(#[case] dir: &str, #[case] name: &str, #[case] want: Option<&str>) {
        let joined = ArchivePath::parse(dir.as_bytes()).unwrap().join(name.as_bytes());
        assert_eq!(joined.map(|p| p.to_string()).as_deref(), want);
    }

    #[rstest]
    #[case::root("", "x", true)]
    #[case::child("a", "a/b", true)]
    #[case::itself("a", "a", false)]
    #[case::sibling_sharing_a_prefix("a", "ab/c", false)]
    #[case::root_itself("", "", false)]
    fn contains_compares_whole_components(#[case] dir: &str, #[case] name: &str, #[case] want: bool) {
        let path = |s: &str| ArchivePath::parse(s.as_bytes()).unwrap();
        assert_eq!(path(dir).contains(&path(name)), want);
    }

    #[test]
    fn ancestors_end_at_the_root() {
        let names: Vec<String> = ArchivePath::parse(b"a/b/c").unwrap().ancestors().map(|p| p.to_string()).collect();
        assert_eq!(names, ["a/b", "a", ""]);
    }
}
