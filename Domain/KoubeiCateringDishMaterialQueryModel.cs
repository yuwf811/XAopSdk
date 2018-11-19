using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// KoubeiCateringDishMaterialQueryModel Data Structure.
    /// </summary>
    [Serializable]
    public class KoubeiCateringDishMaterialQueryModel : AopObject
    {
        /// <summary>
        /// 加料的id
        /// </summary>
        [XmlElement("material_id")]
        public string MaterialId { get; set; }

        /// <summary>
        /// 要查询的加料库的商户id
        /// </summary>
        [XmlElement("merchant_id")]
        public string MerchantId { get; set; }
    }
}
