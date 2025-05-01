namespace ASC.Web.Areas.Configuration.Models
{
    public class MasterValuesViewModel
    {
        public List<MasterDataValueViewModel>? MasterValues { get; set; }
        public MasterDataKeyViewModel? MasterValueInContext { get; set; }
        public bool IsEdit { get; set; }
    }
}