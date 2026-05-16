use crate::error::Result;
use crate::types::QueryType;

pub(crate) trait QueryRecord: Sized + Send + 'static {
    const QUERY_TYPE: QueryType;
    fn parse(data: &[u8]) -> Result<Self>;
}
