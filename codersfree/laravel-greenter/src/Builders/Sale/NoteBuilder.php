<?php

namespace CodersFree\LaravelGreenter\Builders\Sale;

use CodersFree\LaravelGreenter\Builders\Client\ClientBuilder;
use CodersFree\LaravelGreenter\Builders\Company\CompanyBuilder;
use CodersFree\LaravelGreenter\Contracts\DocumentBuilderInterface;
use Greenter\Model\Sale\Note;

class NoteBuilder implements DocumentBuilderInterface
{
    public function build(array $data): Note
    {
        return (new Note())
            //Base Sale
            ->setUblVersion($data['ublVersion'] ?? '2.1')
            ->setTipoDoc($data['tipoDoc'] ?? null)
            ->setSerie($data['serie'] ?? null)
            ->setCorrelativo($data['correlativo'] ?? null)
            ->setFechaEmision(
                isset($data['fechaEmision'])
                    ? new \DateTime($data['fechaEmision'])
                    : null
            )
            ->setCompany(
                (new CompanyBuilder())->build()
            )
            ->setClient(
                isset($data['client'])
                    ? (new ClientBuilder())->build($data['client'])
                    : null
            )
            ->setTipoMoneda($data['tipoMoneda'] ?? null)
            ->setSumOtrosCargos($data['sumOtrosCargos'] ?? null)
            ->setMtoOperGravadas($data['mtoOperGravadas'] ?? null)
            ->setMtoOperInafectas($data['mtoOperInafectas'] ?? null)
            ->setMtoOperExoneradas($data['mtoOperExoneradas'] ?? null)
            ->setMtoOperExportacion($data['mtoOperExportacion'] ?? null)
            ->setMtoOperGratuitas($data['mtoOperGratuitas'] ?? null)
            ->setMtoIGVGratuitas($data['mtoIGVGratuitas'] ?? null)
            ->setMtoIGV($data['mtoIGV'] ?? null)
            ->setMtoBaseIvap($data['mtoBaseIvap'] ?? null)
            ->setMtoIvap($data['mtoIvap'] ?? null)
            ->setMtoBaseIsc($data['mtoBaseIsc'] ?? null)
            ->setMtoIsc($data['mtoIsc'] ?? null)
            ->setMtoBaseOth($data['mtoBaseOth'] ?? null)
            ->setMtoOtrosTributos($data['mtoOtrosTributos'] ?? null)
            ->setIcbper($data['icbper'] ?? null)
            ->setTotalImpuestos($data['totalImpuestos'] ?? null)
            ->setRedondeo($data['redondeo'] ?? null)
            ->setMtoImpVenta($data['mtoImpVenta'] ?? null)
            ->setDetails(
                array_map(
                    fn($detail) => (new SaleDetailBuilder())->build($detail),
                    $data['details'] ?? []
                )
            )
            ->setLegends(
                array_map(
                    fn($legend) => (new LegendBuilder())->build($legend),
                    $data['legends'] ?? []
                )
            )
            ->setGuias(
                array_map(
                    fn($guia) => (new DocumentBuilder())->build($guia),
                    $data['guias'] ?? []
                )
            )
            ->setRelDocs(
                array_map(
                    fn($relDoc) => (new DocumentBuilder())->build($relDoc),
                    $data['relDocs'] ?? []
                )
            )
            ->setCompra($data['compra'] ?? null)
            ->setFormaPago(
                isset($data['formaPago'])
                    ? (new PaymentTermsBuilder())->build($data['formaPago'])
                    : null
            )
            ->setCuotas(
                array_map(
                    fn($cuota) => (new CuotaBuilder())->build($cuota),
                    $data['cuotas'] ?? []
                )
            )

            //Nota de venta
            ->setCodMotivo($data['codMotivo'] ?? null)
            ->setDesMotivo($data['desMotivo'] ?? null)
            ->setTipDocAfectado($data['tipDocAfectado'] ?? null)
            ->setNumDocfectado($data['numDocfectado'] ?? null)
            ->setPerception(
                isset($data['perception']) 
                    ? (new SalePerceptionBuilder())->build($data['perception']) 
                    : null
            )
            ->setValorVenta($data['valorVenta'] ?? null)
            ->setSubTotal($data['subTotal'] ?? null);
    }
}